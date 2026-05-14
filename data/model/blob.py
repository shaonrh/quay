import logging
from datetime import datetime, timedelta
from uuid import uuid4

from peewee import IntegrityError
from prometheus_client import Counter

from data.database import (
    BlobUpload,
    DigestAlias,
    ImageStorage,
    ImageStorageLocation,
    ImageStoragePlacement,
    Namespace,
    Repository,
    RepositoryState,
    UploadedBlob,
    db_random_func,
)
from data.model import (
    BlobDoesNotExist,
    InvalidBlobUpload,
    InvalidImageException,
    _basequery,
    db_transaction,
)
from data.model import storage as storage_model
from data.model.storage import get_or_create_blob_with_lock, with_blob_lock_or_fallback

logger = logging.getLogger(__name__)

digest_alias_created_total = Counter(
    "quay_digest_alias_created_total",
    "Number of DigestAlias records created during blob uploads",
    labelnames=["algorithm"],
)


class DigestAliasCollisionError(Exception):
    """
    Raised when a DigestAlias already exists pointing to a different ImageStorage.
    """


def create_digest_alias(client_digest_str, image_storage, manifest=None):
    """
    Creates a DigestAlias mapping client_digest_str to the given ImageStorage.
    Optionally links to a Manifest (for manifest aliases).
    Idempotent for same-storage mappings. Raises DigestAliasCollisionError on collision.

    Also increments the Prometheus counter for observability.
    """
    try:
        DigestAlias.create(
            digest=client_digest_str,
            image_storage=image_storage,
            manifest=manifest,
        )
        logger.info(
            "Created DigestAlias: %s -> ImageStorage %s (content_checksum=%s, manifest=%s)",
            client_digest_str,
            image_storage.id,
            image_storage.content_checksum,
            manifest.id if manifest else None,
        )
        # Increment Prometheus counter
        algo = client_digest_str.split(":", 1)[0]
        digest_alias_created_total.labels(algo).inc()
    except IntegrityError:
        existing = DigestAlias.get(DigestAlias.digest == client_digest_str)
        if existing.image_storage_id == image_storage.id:
            logger.debug(
                "DigestAlias %s already exists for same ImageStorage %s, skipping",
                client_digest_str,
                image_storage.id,
            )
            return
        else:
            logger.error(
                "DigestAlias collision: %s maps to ImageStorage %s but upload "
                "resolved to ImageStorage %s",
                client_digest_str,
                existing.image_storage_id,
                image_storage.id,
            )
            raise DigestAliasCollisionError(
                f"Hash collision: digest {client_digest_str} maps to different blob"
            )


def resolve_blob_by_digest_alias(blob_digest):
    """
    Resolves a non-SHA-256 digest to an ImageStorage via the DigestAlias table.
    Returns the ImageStorage row or None if no alias exists.
    """
    try:
        alias = DigestAlias.get(DigestAlias.digest == blob_digest)
        return alias.image_storage
    except DigestAlias.DoesNotExist:
        return None


def store_blob_record_and_temp_link(
    namespace,
    repo_name,
    blob_digest,
    location_obj,
    byte_count,
    link_expiration_s,
    uncompressed_byte_count=None,
):
    repo = _basequery.get_existing_repository(namespace, repo_name)
    assert repo

    # When called via old interface, content_checksum = canonical_sha256 = blob_digest
    # (all existing callers pass SHA-256)
    return store_blob_record_and_temp_link_in_repo(
        repo.id,
        blob_digest,
        blob_digest,
        location_obj,
        byte_count,
        link_expiration_s,
        uncompressed_byte_count,
    )


def _store_blob_record_and_temp_link_in_repo(
    repository_id,
    content_checksum,
    canonical_sha256,
    location_obj,
    byte_count,
    link_expiration_s,
    uncompressed_byte_count=None,
    skip_lock=False,
):
    """
    Helper: creates ImageStorage (or reuses existing via canonical_sha256 dedup),
    creates placement, and temp-links to repository.
    """
    with db_transaction():
        # Dedup by canonical_sha256: same content = same SHA-256 = same storage
        existing = (
            ImageStorage.select()
            .where(ImageStorage.canonical_sha256 == canonical_sha256)
            .first()  # .first() not .get() -- handles rare multi-row case
        )

        if existing is not None:
            storage = existing
            save_changes = False

            if storage.image_size is None:
                storage.image_size = byte_count
                save_changes = True

            if storage.uncompressed_size is None and uncompressed_byte_count is not None:
                storage.uncompressed_size = uncompressed_byte_count
                save_changes = True

            if save_changes:
                storage.save()

            # If client used a different digest than what's stored, create DigestAlias
            # so the client's digest is retrievable (OQ5 resolution: Option a)
            if content_checksum != storage.content_checksum:
                try:
                    create_digest_alias(content_checksum, storage)
                except DigestAliasCollisionError:
                    # Another ImageStorage has this digest -- should not happen
                    # with correct content-addressing, but log and continue
                    logger.warning(
                        "DigestAlias collision for %s during dedup",
                        content_checksum,
                    )
        else:
            # No existing storage -- create new
            storage = get_or_create_blob_with_lock(
                content_checksum=content_checksum,
                canonical_sha256=canonical_sha256,
                image_size=byte_count,
                uncompressed_size=uncompressed_byte_count,
                skip_lock=skip_lock,
            )

        try:
            ImageStoragePlacement.get(storage=storage, location=location_obj)
        except ImageStoragePlacement.DoesNotExist:
            try:
                ImageStoragePlacement.create(storage=storage, location=location_obj)
            except IntegrityError as e:
                logger.warning(
                    "Another worker already created placement for blob %s: %s",
                    canonical_sha256,
                    e,
                )

        _temp_link_blob(repository_id, storage, link_expiration_s)
        return storage


def store_blob_record_and_temp_link_in_repo(
    repository_id,
    content_checksum,
    canonical_sha256,
    location_obj,
    byte_count,
    link_expiration_s,
    uncompressed_byte_count=None,
):
    """
    Store a record of the blob and temporarily link it to the specified repository.

    Lock coordination uses canonical_sha256 to match GC's lock key.
    Dedup uses canonical_sha256 to find existing storage for same content.
    """
    assert content_checksum
    assert canonical_sha256
    assert byte_count is not None

    # Lock on canonical_sha256 -- same key GC uses for deletion coordination
    return with_blob_lock_or_fallback(
        canonical_sha256,
        _store_blob_record_and_temp_link_in_repo,
        repository_id=repository_id,
        content_checksum=content_checksum,
        canonical_sha256=canonical_sha256,
        location_obj=location_obj,
        byte_count=byte_count,
        link_expiration_s=link_expiration_s,
        uncompressed_byte_count=uncompressed_byte_count,
    )


def temp_link_blob(repository_id, blob_digest, link_expiration_s):
    """
    Temporarily links to the blob record from the given repository.

    Supports lookup by either content_checksum or canonical_sha256, so that:
    - Direct digest lookups work (content_checksum match)
    - SHA-256 lookups work for blobs uploaded with non-SHA-256 (canonical_sha256 match)
    - Feature flag rollback doesn't break blob access

    If the blob record is not found, return None.
    """
    assert blob_digest

    with db_transaction():
        # Try content_checksum first (direct match)
        try:
            storage = ImageStorage.get(content_checksum=blob_digest)
        except ImageStorage.DoesNotExist:
            # Fallback: try canonical_sha256 (SHA-256 lookup for non-SHA-256 blobs)
            storage = (
                ImageStorage.select().where(ImageStorage.canonical_sha256 == blob_digest).first()
            )
            if storage is None:
                return None

        _temp_link_blob(repository_id, storage, link_expiration_s)
        return storage


def _temp_link_blob(repository_id, storage, link_expiration_s):
    """Note: Should *always* be called by a parent under a transaction."""
    try:
        repository = Repository.get(id=repository_id)
    except Repository.DoesNotExist:
        return None

    if repository.state == RepositoryState.MARKED_FOR_DELETION:
        return None

    return UploadedBlob.create(
        repository=repository_id,
        blob=storage,
        expires_at=datetime.utcnow() + timedelta(seconds=link_expiration_s),
    )


def lookup_expired_uploaded_blobs(repository):
    """Looks up all expired uploaded blobs in a repository."""
    return UploadedBlob.select().where(
        UploadedBlob.repository == repository, UploadedBlob.expires_at <= datetime.utcnow()
    )


def get_stale_blob_upload(stale_timespan):
    """
    Returns a blob upload which was created before the stale timespan.
    """
    stale_threshold = datetime.now() - stale_timespan

    try:
        candidates = (
            BlobUpload.select(BlobUpload, ImageStorageLocation)
            .join(ImageStorageLocation)
            .where(BlobUpload.created <= stale_threshold)
        )

        return candidates.get()
    except BlobUpload.DoesNotExist:
        return None


def get_blob_upload_by_uuid(upload_uuid):
    """
    Loads the upload with the given UUID, if any.
    """
    try:
        return (
            BlobUpload.select(BlobUpload, ImageStorageLocation)
            .join(ImageStorageLocation)
            .where(BlobUpload.uuid == upload_uuid)
            .get()
        )
    except BlobUpload.DoesNotExist:
        return None


def initiate_upload(namespace, repo_name, uuid, location_name, storage_metadata):
    """
    Initiates a blob upload for the repository with the given namespace and name, in a specific
    location.
    """
    repo = _basequery.get_existing_repository(namespace, repo_name)
    return initiate_upload_for_repo(repo, uuid, location_name, storage_metadata)


def initiate_upload_for_repo(repo, uuid, location_name, storage_metadata):
    """
    Initiates a blob upload for a specific repository object, in a specific location.
    """
    location = storage_model.get_image_location_for_name(location_name)
    return BlobUpload.create(
        repository=repo, location=location.id, uuid=uuid, storage_metadata=storage_metadata
    )


def get_shared_blob(digest):
    """
    Returns the ImageStorage blob with the given digest or, if not present, returns None.

    This method is *only* to be used for shared blobs that are globally accessible, such as the
    special empty gzipped tar layer that Docker no longer pushes to us.
    """
    assert digest
    try:
        return ImageStorage.get(content_checksum=digest)
    except ImageStorage.DoesNotExist:
        return None


def get_or_create_shared_blob(digest, byte_data, storage):
    """
    Returns the ImageStorage blob with the given digest or, if not present, adds a row and writes
    the given byte data to the storage engine.

    This method is *only* to be used for shared blobs that are globally accessible, such as the
    special empty gzipped tar layer that Docker no longer pushes to us.
    """
    assert digest
    assert byte_data is not None and isinstance(byte_data, bytes)
    assert storage

    try:
        return ImageStorage.get(content_checksum=digest)
    except ImageStorage.DoesNotExist:
        preferred = storage.preferred_locations[0]
        location_obj = ImageStorageLocation.get(name=preferred)

        record = get_or_create_blob_with_lock(digest=digest, image_size=len(byte_data))

        try:
            storage.put_content([preferred], storage_model.get_layer_path(record), byte_data)
            ImageStoragePlacement.create(storage=record, location=location_obj)
        except IntegrityError as e:
            logger.warning("Exception when trying to write special layer %s: %s", digest, e)

        return record

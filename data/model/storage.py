import logging
from collections import namedtuple

from cachetools.func import lru_cache
from peewee import SQL, IntegrityError

from data.database import (
    DigestAlias,
    ImageStorage,
    ImageStorageLocation,
    ImageStoragePlacement,
    ImageStorageSignature,
    ImageStorageSignatureKind,
    ImageStorageTransformation,
    ManifestBlob,
    Namespace,
    Repository,
    UploadedBlob,
    ensure_under_transaction,
)
from data.model import (
    DataModelException,
    InvalidImageException,
    _basequery,
    config,
    db_transaction,
)
from util.locking import GlobalLock, LockNotAcquiredException
from util.metrics.prometheus import gc_storage_blobs_deleted, gc_table_rows_deleted

logger = logging.getLogger(__name__)

_Location = namedtuple("_Location", ["id", "name"])

EMPTY_LAYER_BLOB_DIGEST = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
SPECIAL_BLOB_DIGESTS = set([EMPTY_LAYER_BLOB_DIGEST])


@lru_cache(maxsize=1)
def get_image_locations():
    location_map = {}
    for location in ImageStorageLocation.select():
        location_tuple = _Location(location.id, location.name)
        location_map[location.id] = location_tuple
        location_map[location.name] = location_tuple

    return location_map


def get_image_location_for_name(location_name):
    locations = get_image_locations()
    return locations[location_name]


def get_image_location_for_id(location_id):
    locations = get_image_locations()
    return locations[location_id]


def add_storage_placement(storage, location_name):
    """
    Adds a storage placement for the given storage at the given location.
    """
    location = get_image_location_for_name(location_name)
    try:
        ImageStoragePlacement.create(location=location.id, storage=storage)
    except IntegrityError:
        # Placement already exists. Nothing to do.
        pass


def _is_storage_orphaned(candidate_id):
    """
    Returns the whether the given candidate storage ID is orphaned. Must be executed
    under a transaction.
    """
    with ensure_under_transaction():
        try:
            ManifestBlob.get(blob=candidate_id)
            return False
        except ManifestBlob.DoesNotExist:
            pass

        try:
            UploadedBlob.get(blob=candidate_id)
            return False
        except UploadedBlob.DoesNotExist:
            pass

        # Check DigestAlias references
        try:
            DigestAlias.get(image_storage=candidate_id)
            return False
        except DigestAlias.DoesNotExist:
            pass

        # We need to check if a blob is a placeholder blob. If it is, we must **NOT** delete this blob.
        has_placement = (
            ImageStoragePlacement.select()
            .where(ImageStoragePlacement.storage == candidate_id)
            .exists()
        )

        if not has_placement:
            # Placeholder blobs will be GCed later in a future cycle or the download worker will download it
            logger.debug("Skipping GC of placeholder blob %s (no placement yet)", candidate_id)
            return False

    return True


def garbage_collect_storage(storage_id_whitelist):
    """
    Performs GC on a possible subset of the storage's with the IDs found in the whitelist.

    The storages in the whitelist will be checked, and any orphaned will be removed, with those IDs
    being returned.
    """
    if len(storage_id_whitelist) == 0:
        return []

    # Pre-pass: clean up DigestAlias rows for storage with no other live references
    for storage_id in storage_id_whitelist:
        with db_transaction():
            has_manifest_ref = ManifestBlob.select().where(ManifestBlob.blob == storage_id).exists()
            has_upload_ref = UploadedBlob.select().where(UploadedBlob.blob == storage_id).exists()
            if not has_manifest_ref and not has_upload_ref:
                deleted = (
                    DigestAlias.delete().where(DigestAlias.image_storage == storage_id).execute()
                )
                if deleted:
                    logger.info(
                        "GC pre-pass: deleted %d orphaned DigestAlias rows " "for storage %s",
                        deleted,
                        storage_id,
                    )
                    gc_table_rows_deleted.labels(table="DigestAlias").inc(deleted)

    # Clean up manifest aliases pointing to deleted manifests (subquery-based)
    with db_transaction():
        from data.database import Manifest

        stale_alias_subquery = (
            DigestAlias.select(DigestAlias.id)
            .where(DigestAlias.manifest.is_null(False))
            .where(
                ~(Manifest.select(Manifest.id).where(Manifest.id == DigestAlias.manifest).exists())
            )
        )
        deleted_stale = (
            DigestAlias.delete().where(DigestAlias.id.in_(stale_alias_subquery)).execute()
        )
        if deleted_stale:
            gc_table_rows_deleted.labels(table="DigestAlias").inc(deleted_stale)

    def placements_to_filtered_paths_set(placements_list):
        """
        Returns paths to remove from storage, filtered by removing any CAS paths
        still referenced by storage(s) in the database.

        Uses canonical_sha256 for CAS dedup checks -- two ImageStorage rows with
        different content_checksum but same canonical_sha256 reference the same
        physical CAS path.
        """
        if not placements_list:
            return set()

        with ensure_under_transaction():
            # Collect canonical_sha256 values for CAS placements
            canonical_checksums = set(
                placement.storage.effective_canonical_sha256
                for placement in placements_list
                if placement.storage.cas_path
            )

            unreferenced_checksums = set()
            if canonical_checksums:
                # Check if any ImageStorage still references these canonical_sha256 values
                query = ImageStorage.select(ImageStorage.canonical_sha256).where(
                    ImageStorage.canonical_sha256 << list(canonical_checksums)
                )
                is_referenced_checksums = set(
                    image_storage.canonical_sha256 for image_storage in query
                )
                if is_referenced_checksums:
                    logger.warning(
                        "GC attempted to remove CAS checksums %s, which are still IS referenced",
                        is_referenced_checksums,
                    )
                unreferenced_checksums = canonical_checksums - is_referenced_checksums

            return {
                (
                    get_image_location_for_id(placement.location_id).name,
                    get_layer_path(placement.storage),
                    placement.storage.effective_canonical_sha256,
                )
                for placement in placements_list
                if not placement.storage.cas_path
                or placement.storage.effective_canonical_sha256 in unreferenced_checksums
            }

    # Note: Both of these deletes must occur in the same transaction (unfortunately) because a
    # storage without any placement is invalid, and a placement cannot exist without a storage.
    # TODO: We might want to allow for null storages on placements, which would allow us to
    # delete the storages, then delete the placements in a non-transaction.
    logger.debug("Garbage collecting storages from candidates: %s", storage_id_whitelist)
    paths_to_remove = []
    orphaned_storage_ids = set()
    for storage_id_to_check in storage_id_whitelist:
        logger.debug("Garbage collecting storage %s", storage_id_to_check)

        with db_transaction():
            if not _is_storage_orphaned(storage_id_to_check):
                continue

            orphaned_storage_ids.add(storage_id_to_check)

            placements_to_remove = list(
                ImageStoragePlacement.select(ImageStoragePlacement, ImageStorage)
                .join(ImageStorage)
                .where(ImageStorage.id == storage_id_to_check)
            )

            # Remove the placements for orphaned storages
            deleted_image_storage_placement = 0
            if placements_to_remove:
                deleted_image_storage_placement = (
                    ImageStoragePlacement.delete()
                    .where(ImageStoragePlacement.storage == storage_id_to_check)
                    .execute()
                )

            deleted_image_storage_signature = (
                ImageStorageSignature.delete()
                .where(ImageStorageSignature.storage == storage_id_to_check)
                .execute()
            )

            # Delete DigestAlias rows before ImageStorage deletion
            deleted_digest_alias = (
                DigestAlias.delete()
                .where(DigestAlias.image_storage == storage_id_to_check)
                .execute()
            )

            deleted_image_storage = (
                ImageStorage.delete().where(ImageStorage.id == storage_id_to_check).execute()
            )

            # Determine the paths to remove. We cannot simply remove all paths matching storages, as CAS
            # can share the same path. We further filter these paths by checking for any storages still in
            # the database with the same content checksum.
            paths_to_remove.extend(placements_to_filtered_paths_set(placements_to_remove))

        gc_table_rows_deleted.labels(table="DigestAlias").inc(deleted_digest_alias)
        gc_table_rows_deleted.labels(table="ImageStorageSignature").inc(
            deleted_image_storage_signature
        )
        gc_table_rows_deleted.labels(table="ImageStorage").inc(deleted_image_storage)
        gc_table_rows_deleted.labels(table="ImageStoragePlacement").inc(
            deleted_image_storage_placement
        )

    # We are going to make the conscious decision to not delete image storage blobs inside
    # transactions.
    # This may end up producing garbage in s3, trading off for higher availability in the database.
    paths_to_remove = list(set(paths_to_remove))
    for location_name, image_path, storage_checksum in paths_to_remove:
        if storage_checksum:
            # storage_checksum is now canonical_sha256 (always sha256:...)
            # from placements_to_filtered_paths_set

            # Skip any specialized blob digests that we know we should keep around.
            if storage_checksum in SPECIAL_BLOB_DIGESTS:
                continue

            # Lock on canonical_sha256 -- same key used by blob creation
            try:
                with GlobalLock(f"BLOB_DELETE_{storage_checksum}", lock_ttl=120):
                    # Final safety check: any ImageStorage still references this SHA-256?
                    if (
                        ImageStorage.select()
                        .where(ImageStorage.canonical_sha256 == storage_checksum)
                        .exists()
                    ):
                        continue

                    logger.debug("Removing %s from %s", image_path, location_name)
                    config.store.remove({location_name}, image_path)
                    gc_storage_blobs_deleted.inc()
            except LockNotAcquiredException:
                logger.debug(
                    "Could not acquire lock for blob %s, skipping deletion",
                    storage_checksum,
                )
                continue
    return orphaned_storage_ids


def create_v1_storage(location_name):
    storage = ImageStorage.create(cas_path=False)
    location = get_image_location_for_name(location_name)
    ImageStoragePlacement.create(location=location.id, storage=storage)
    storage.locations = {location_name}
    return storage


def find_or_create_storage_signature(storage, signature_kind_name):
    found = lookup_storage_signature(storage, signature_kind_name)
    if found is None:
        kind = ImageStorageSignatureKind.get(name=signature_kind_name)
        found = ImageStorageSignature.create(storage=storage, kind=kind)

    return found


def lookup_storage_signature(storage, signature_kind_name):
    kind = ImageStorageSignatureKind.get(name=signature_kind_name)
    try:
        return (
            ImageStorageSignature.select()
            .where(ImageStorageSignature.storage == storage, ImageStorageSignature.kind == kind)
            .get()
        )
    except ImageStorageSignature.DoesNotExist:
        return None


def _get_storage(query_modifier):
    query = (
        ImageStoragePlacement.select(ImageStoragePlacement, ImageStorage)
        .switch(ImageStoragePlacement)
        .join(ImageStorage)
    )

    placements = list(query_modifier(query))

    if not placements:
        raise InvalidImageException()

    found = placements[0].storage
    found.locations = {
        get_image_location_for_id(placement.location_id).name for placement in placements
    }
    return found


def with_blob_lock_or_fallback(digest, func, *args, **kwargs):
    """
    Execute a function with GlobalLock protection, falling back to per-operation locking if unavailable.

    This helper consolidates the common pattern of:
    1. Try to acquire GlobalLock for blob deletion coordination (outer lock)
    2. Execute func with skip_lock=True (caller holds lock)
    3. If outer lock acquisition fails, execute func with skip_lock=False (per-operation locking)

    The primary purpose is to coordinate with garbage collection (GC) to prevent the race condition
    where GC deletes a blob from object storage while another operation is creating database entries
    for that same blob.

    Args:
        digest: Blob digest for lock key (e.g., "sha256:abc123...")
        func: Callable to execute (must accept skip_lock kwarg)
        *args, **kwargs: Arguments to pass to func

    Returns:
        Result of func()

    Fallback behavior:
        If the global lock is unavailable (e.g., GC holds it or Redis is down), the function
        delegates locking to the called function by passing skip_lock=False. This allows the
        operation to proceed with per-operation locking. If Redis is completely unavailable,
        the final fallback is lockless creation, which means the race condition can *still*
        happen, but the window is extremely narrow. In this scenario, database uniqueness
        constraints provide the ultimate safety guarantee. This lockless creation is the same
        as the logic that existed before the race condition fix.
    """
    try:
        with GlobalLock(f"BLOB_DELETE_{digest}", lock_ttl=30):
            return func(*args, skip_lock=True, **kwargs)
    except LockNotAcquiredException as e:
        logger.warning("Could not acquire lock for blob %s: %s", digest, e)
        logger.warning("Falling back to per-operation locking.")
        return func(*args, skip_lock=False, **kwargs)


def _get_or_create_blob_with_lock(
    content_checksum, canonical_sha256, lock_acquired=True, **blob_attrs
):
    """
    Gets or creates the ImageStorage reference. Dedup lookup by canonical_sha256.
    Creates with both content_checksum and canonical_sha256.
    """
    # Try to find existing by canonical_sha256 (dedup)
    existing = (
        ImageStorage.select().where(ImageStorage.canonical_sha256 == canonical_sha256).first()
    )
    if existing is not None:
        return existing

    if not lock_acquired:
        logger.warning("Creating blob %s without lock as fallback", canonical_sha256)
    try:
        return ImageStorage.create(
            content_checksum=content_checksum,
            canonical_sha256=canonical_sha256,
            **blob_attrs,
        )
    except IntegrityError as e:
        logger.warning("Another worker already created blob %s: %s", canonical_sha256, e)
        existing = (
            ImageStorage.select().where(ImageStorage.canonical_sha256 == canonical_sha256).first()
        )
        if existing is not None:
            return existing
        # Ultimate fallback: try by content_checksum
        return ImageStorage.get(content_checksum=content_checksum)


def get_or_create_blob_with_lock(
    content_checksum=None, canonical_sha256=None, digest=None, skip_lock=False, **blob_attrs
):
    """
    Atomically gets or creates an ImageStorage blob, coordinating with GC deletion.

    Lock key is canonical_sha256 (always SHA-256) to match GC's lock key.
    Lookup and creation use canonical_sha256 for dedup.

    Args:
        content_checksum: Client-facing digest (algorithm-agnostic)
        canonical_sha256: Always SHA-256 digest for lock key and dedup
        digest: Legacy parameter -- used as both content_checksum and canonical_sha256
            when the new parameters are not provided (backward compatibility)
        skip_lock: If True, assume caller holds the lock
        **blob_attrs: Additional attributes to pass to ImageStorage.create()

    Returns:
        ImageStorage object (either existing or newly created)
    """
    # Backward compatibility: if 'digest' is passed but not the new params,
    # use it for both (existing callers always pass SHA-256)
    if content_checksum is None and digest is not None:
        content_checksum = digest
    if canonical_sha256 is None and digest is not None:
        canonical_sha256 = digest
    if canonical_sha256 is None:
        canonical_sha256 = content_checksum

    if skip_lock:
        return _get_or_create_blob_with_lock(
            content_checksum, canonical_sha256, lock_acquired=True, **blob_attrs
        )
    if GlobalLock.lock_factory is None:
        return _get_or_create_blob_with_lock(
            content_checksum, canonical_sha256, lock_acquired=False, **blob_attrs
        )
    try:
        with GlobalLock(f"BLOB_DELETE_{canonical_sha256}", lock_ttl=30):
            return _get_or_create_blob_with_lock(
                content_checksum, canonical_sha256, lock_acquired=True, **blob_attrs
            )
    except LockNotAcquiredException:
        return _get_or_create_blob_with_lock(
            content_checksum, canonical_sha256, lock_acquired=False, **blob_attrs
        )


def get_storage_by_uuid(storage_uuid):
    def filter_to_uuid(query):
        return query.where(ImageStorage.uuid == storage_uuid)

    try:
        return _get_storage(filter_to_uuid)
    except InvalidImageException:
        raise InvalidImageException("No storage found with uuid: %s", storage_uuid)


def get_layer_path(storage_record):
    """
    Returns the path in the storage engine to the layer data referenced by the storage row.
    Uses canonical_sha256 for CAS path computation.
    """
    assert storage_record.cas_path is not None
    return get_layer_path_for_storage(
        storage_record.uuid,
        storage_record.cas_path,
        storage_record.effective_canonical_sha256,
    )


def get_layer_path_for_storage(storage_uuid, cas_path, content_checksum):
    """
    Returns the path in the storage engine to the layer data referenced by the storage information.
    """
    store = config.store
    if not cas_path:
        logger.debug("Serving layer from legacy v1 path for storage %s", storage_uuid)
        return store.v1_image_layer_path(storage_uuid)

    return store.blob_path(content_checksum)


def lookup_repo_storages_by_content_checksum(repo, checksums, with_uploads=False):
    """
    Looks up repository storages (without placements) matching the given repository and checksum.
    """
    checksums = list(set(checksums))
    if not checksums:
        return []

    # If the request is not with uploads, simply return the blobs found under the manifests
    # for the repository.
    if not with_uploads:
        return _lookup_repo_storages_by_content_checksum(repo, checksums, ManifestBlob)

    # Otherwise, first check the UploadedBlob table and, once done, then check the ManifestBlob
    # table.
    found_via_uploaded = list(
        _lookup_repo_storages_by_content_checksum(repo, checksums, UploadedBlob)
    )
    if len(found_via_uploaded) == len(checksums):
        return found_via_uploaded

    checksums_remaining = set(checksums) - {
        uploaded.content_checksum for uploaded in found_via_uploaded
    }
    found_via_manifest = list(
        _lookup_repo_storages_by_content_checksum(repo, checksums_remaining, ManifestBlob)
    )
    return found_via_uploaded + found_via_manifest


def _lookup_repo_storages_by_content_checksum(repo, checksums, model_class):
    assert checksums

    # There may be many duplicates of the checksums, so for performance reasons we are going
    # to use a union to select just one storage with each checksum
    queries = []

    for counter, checksum in enumerate(checksums):
        query_alias = "q{0}".format(counter)

        candidate_subq = (
            ImageStorage.select(
                ImageStorage.id,
                ImageStorage.content_checksum,
                ImageStorage.image_size,
                ImageStorage.uuid,
                ImageStorage.cas_path,
                ImageStorage.uncompressed_size,
            )
            .join(model_class)
            .where(model_class.repository == repo, ImageStorage.content_checksum == checksum)
            .limit(1)
            .alias(query_alias)
        )

        queries.append(ImageStorage.select(SQL("*")).from_(candidate_subq))

    assert queries

    # Prevent crash on gunicorn (PROJQUAY-7603)
    # If the number of queries is too large, the UNION query
    # generated crashes gunicorn, instead run each query
    # individually
    if len(queries) > 1000:
        result = [next(iter(q.execute()), None) for q in queries]
        return [r for r in result if r is not None]

    return _basequery.reduce_as_tree(queries)


def lookup_repo_storages_by_canonical_sha256(repo, checksums, with_uploads=False):
    """
    Looks up repository storages by canonical_sha256 values.
    Same structure as lookup_repo_storages_by_content_checksum but queries
    canonical_sha256 instead.
    """
    if not checksums:
        return []

    if not with_uploads:
        return _lookup_repo_storages_by_canonical_sha256(repo, checksums, ManifestBlob)

    # Check UploadedBlob first, then ManifestBlob for remaining
    found_via_uploaded = list(
        _lookup_repo_storages_by_canonical_sha256(repo, checksums, UploadedBlob)
    )
    if len(found_via_uploaded) == len(checksums):
        return found_via_uploaded

    checksums_remaining = set(checksums) - {
        uploaded.canonical_sha256 for uploaded in found_via_uploaded
    }
    found_via_manifest = list(
        _lookup_repo_storages_by_canonical_sha256(repo, checksums_remaining, ManifestBlob)
    )
    return found_via_uploaded + found_via_manifest


def _lookup_repo_storages_by_canonical_sha256(repo, checksums, model_class):
    """
    Inner lookup using balanced union trees via _basequery.reduce_as_tree.
    Mirrors _lookup_repo_storages_by_content_checksum exactly, querying
    canonical_sha256 instead of content_checksum.
    """
    assert checksums

    queries = []
    for counter, checksum in enumerate(checksums):
        query_alias = "q{0}".format(counter)

        candidate_subq = (
            ImageStorage.select(
                ImageStorage.id,
                ImageStorage.content_checksum,
                ImageStorage.canonical_sha256,
                ImageStorage.image_size,
                ImageStorage.uuid,
                ImageStorage.cas_path,
                ImageStorage.uncompressed_size,
            )
            .join(model_class)
            .where(
                model_class.repository == repo,
                ImageStorage.canonical_sha256 == checksum,
            )
            .limit(1)
            .alias(query_alias)
        )

        queries.append(ImageStorage.select(SQL("*")).from_(candidate_subq))

    assert queries

    # Prevent crash on gunicorn (PROJQUAY-7603)
    if len(queries) > 1000:
        result = [next(iter(q.execute()), None) for q in queries]
        return [r for r in result if r is not None]

    return _basequery.reduce_as_tree(queries)


def get_storage_locations(uuid):
    query = ImageStoragePlacement.select().join(ImageStorage).where(ImageStorage.uuid == uuid)

    return [get_image_location_for_id(placement.location_id).name for placement in query]


def ensure_image_locations(*names):
    with db_transaction():
        locations = ImageStorageLocation.select().where(ImageStorageLocation.name << names)

        insert_names = list(names)

        for location in locations:
            insert_names.remove(location.name)

        if not insert_names:
            return

        data = [{"name": name} for name in insert_names]
        ImageStorageLocation.insert_many(data).execute()

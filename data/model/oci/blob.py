from data.database import ImageStorage, ManifestBlob, UploadedBlob
from data.model import BlobDoesNotExist
from data.model.storage import InvalidImageException, get_storage_by_uuid


def get_repository_blob_by_canonical_sha256(repository_id, canonical_sha256):
    """
    Looks up a blob in a repository by its canonical SHA-256 digest.
    Follows the same pattern as get_repository_blob_by_digest:
    select uuid, then get_storage_by_uuid for the full record.
    """
    # Try via ManifestBlob first
    try:
        storage = (
            ImageStorage.select(ImageStorage.uuid)
            .join(ManifestBlob, on=(ManifestBlob.blob == ImageStorage.id))
            .where(
                ManifestBlob.repository == repository_id,
                ImageStorage.canonical_sha256 == canonical_sha256,
            )
            .get()
        )
        return get_storage_by_uuid(storage.uuid)
    except ImageStorage.DoesNotExist:
        pass

    # Fallback: try via UploadedBlob (temp links)
    try:
        storage = (
            ImageStorage.select(ImageStorage.uuid)
            .join(UploadedBlob, on=(UploadedBlob.blob == ImageStorage.id))
            .where(
                UploadedBlob.repository == repository_id,
                ImageStorage.canonical_sha256 == canonical_sha256,
            )
            .get()
        )
        return get_storage_by_uuid(storage.uuid)
    except ImageStorage.DoesNotExist:
        return None


def get_repository_blob_by_digest(repository, blob_digest):
    """
    Find the content-addressable blob linked to the specified repository and returns it or None if
    none.
    """
    # First try looking for a recently uploaded blob. If none found that is matching,
    # check the repository itself.
    storage = _lookup_blob_uploaded(repository, blob_digest)
    if storage is None:
        storage = _lookup_blob_in_repository(repository, blob_digest)

    return get_storage_by_uuid(storage.uuid) if storage is not None else None


def _lookup_blob_uploaded(repository, blob_digest):
    try:
        return (
            ImageStorage.select(ImageStorage.uuid)
            .join(UploadedBlob)
            .where(
                UploadedBlob.repository == repository,
                ImageStorage.content_checksum == blob_digest,
            )
            .get()
        )
    except ImageStorage.DoesNotExist:
        return None


def _lookup_blob_in_repository(repository, blob_digest):
    try:
        return (
            ImageStorage.select(ImageStorage.uuid)
            .join(ManifestBlob)
            .where(
                ManifestBlob.repository == repository,
                ImageStorage.content_checksum == blob_digest,
            )
            .get()
        )
    except ImageStorage.DoesNotExist:
        return None

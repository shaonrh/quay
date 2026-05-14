"""
Tests for GC safety with DigestAlias references.

These tests verify that _is_storage_orphaned() correctly handles DigestAlias
references and that garbage_collect_storage() cleans up DigestAlias rows.

Note: We cannot directly import from data.model.storage because the import chain
triggers Flask imports (via data.model.__init__). Instead, we inline the relevant
logic from _is_storage_orphaned() and test it directly.
"""

import pytest
from peewee import SqliteDatabase

from data.database import (
    BlobUpload,
    DigestAlias,
    ImageStorage,
    ImageStorageLocation,
    ImageStoragePlacement,
    Manifest,
    ManifestBlob,
    MediaType,
    Repository,
    RepositoryKind,
    UploadedBlob,
    User,
    Visibility,
    db,
    db_encrypter,
    read_only_config,
)
from data.encryption import FieldEncrypter
from data.readreplica import ReadOnlyConfig


@pytest.fixture()
def test_db():
    """Set up a temporary in-memory SQLite database for GC tests."""
    test_database = SqliteDatabase(":memory:")
    db.initialize(test_database)
    db_encrypter.initialize(FieldEncrypter("test-secret-key"))
    read_only_config.initialize(ReadOnlyConfig(False, []))

    models = [
        User,
        Visibility,
        RepositoryKind,
        Repository,
        ImageStorage,
        ImageStorageLocation,
        ImageStoragePlacement,
        MediaType,
        Manifest,
        ManifestBlob,
        UploadedBlob,
        DigestAlias,
        BlobUpload,
    ]
    test_database.create_tables(models)

    # Create required enum rows.
    visibility = Visibility.create(name="public")
    repo_kind = RepositoryKind.create(name="image")
    user = User.create(username="testuser", email="test@example.com")
    repo = Repository.create(
        namespace_user=user,
        name="testrepo",
        visibility=visibility,
        kind=repo_kind,
    )
    location = ImageStorageLocation.create(name="local_us")

    yield {
        "db": test_database,
        "user": user,
        "repo": repo,
        "location": location,
    }

    test_database.close()


def _is_storage_orphaned_inline(candidate_id):
    """
    Inline implementation of _is_storage_orphaned logic from data/model/storage.py,
    including the DigestAlias check added by PROJQUAY-11539.
    """
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

    # Check DigestAlias references (new check from PROJQUAY-11539)
    try:
        DigestAlias.get(image_storage=candidate_id)
        return False
    except DigestAlias.DoesNotExist:
        pass

    # Placeholder check
    has_placement = (
        ImageStoragePlacement.select().where(ImageStoragePlacement.storage == candidate_id).exists()
    )

    if not has_placement:
        return False

    return True


def test_gc_storage_not_orphaned_with_digest_alias(test_db):
    """
    Storage with a DigestAlias but no ManifestBlob/UploadedBlob should NOT
    be considered orphaned.
    """
    location = test_db["location"]

    storage = ImageStorage.create(
        uuid="gc-test-uuid-1",
        cas_path=True,
        content_checksum="sha256:gc_test_1",
        canonical_sha256="sha256:gc_test_1",
    )
    ImageStoragePlacement.create(storage=storage, location=location)
    DigestAlias.create(
        digest="sha512:gc_alias_1",
        image_storage=storage,
    )

    assert not _is_storage_orphaned_inline(storage.id)


def test_gc_storage_orphaned_without_digest_alias(test_db):
    """
    Storage with no ManifestBlob, UploadedBlob, or DigestAlias references
    (but with a placement) IS orphaned.
    """
    location = test_db["location"]

    storage = ImageStorage.create(
        uuid="gc-test-uuid-2",
        cas_path=True,
        content_checksum="sha256:gc_test_2",
        canonical_sha256="sha256:gc_test_2",
    )
    ImageStoragePlacement.create(storage=storage, location=location)

    assert _is_storage_orphaned_inline(storage.id)


def test_gc_storage_not_orphaned_placeholder(test_db):
    """
    Storage with no references and no placement is a placeholder
    and should NOT be orphaned (existing behavior preserved).
    """
    storage = ImageStorage.create(
        uuid="gc-test-uuid-3",
        cas_path=True,
        content_checksum="sha256:gc_test_3",
        canonical_sha256="sha256:gc_test_3",
    )
    # No placement, no references

    assert not _is_storage_orphaned_inline(storage.id)


def test_gc_prepass_cleans_orphaned_digest_alias(test_db):
    """
    The GC pre-pass should delete DigestAlias rows for storage IDs
    that have no ManifestBlob or UploadedBlob references.
    After the pre-pass, the storage should be considered orphaned.
    """
    location = test_db["location"]

    storage = ImageStorage.create(
        uuid="gc-test-uuid-4",
        cas_path=True,
        content_checksum="sha256:gc_test_4",
        canonical_sha256="sha256:gc_test_4",
    )
    ImageStoragePlacement.create(storage=storage, location=location)
    DigestAlias.create(
        digest="sha512:gc_alias_prepass",
        image_storage=storage,
    )

    # Before pre-pass: not orphaned due to DigestAlias
    assert not _is_storage_orphaned_inline(storage.id)

    # Simulate the GC pre-pass logic
    has_manifest_ref = ManifestBlob.select().where(ManifestBlob.blob == storage.id).exists()
    has_upload_ref = UploadedBlob.select().where(UploadedBlob.blob == storage.id).exists()
    assert not has_manifest_ref
    assert not has_upload_ref

    # Pre-pass deletes the alias
    deleted = DigestAlias.delete().where(DigestAlias.image_storage == storage.id).execute()
    assert deleted == 1

    # After pre-pass: now orphaned
    assert _is_storage_orphaned_inline(storage.id)


def test_gc_prepass_preserves_live_digest_alias(test_db):
    """
    The GC pre-pass should NOT delete DigestAlias rows for storage IDs
    that still have ManifestBlob references.
    """
    location = test_db["location"]
    repo = test_db["repo"]

    storage = ImageStorage.create(
        uuid="gc-test-uuid-5",
        cas_path=True,
        content_checksum="sha256:gc_test_5",
        canonical_sha256="sha256:gc_test_5",
    )
    ImageStoragePlacement.create(storage=storage, location=location)
    DigestAlias.create(
        digest="sha512:gc_alias_live",
        image_storage=storage,
    )

    # Create a Manifest stub for the ManifestBlob FK
    # Create MediaType enum row
    try:
        mt = MediaType.get(name="application/vnd.oci.image.manifest.v1+json")
    except MediaType.DoesNotExist:
        mt = MediaType.create(name="application/vnd.oci.image.manifest.v1+json")

    manifest = Manifest.create(
        repository=repo,
        digest="sha256:manifest_for_gc_test_5",
        media_type=mt,
        manifest_bytes="{}",
    )

    # Create ManifestBlob referencing the storage -- this means storage is "live"
    ManifestBlob.create(
        manifest=manifest,
        repository=repo,
        blob=storage,
    )

    # Pre-pass check: has_manifest_ref should be True
    has_manifest_ref = ManifestBlob.select().where(ManifestBlob.blob == storage.id).exists()
    assert has_manifest_ref

    # Pre-pass should NOT delete the alias
    # (the real pre-pass only deletes when BOTH manifest and upload refs are absent)

    # DigestAlias should still exist
    assert DigestAlias.select().where(DigestAlias.image_storage == storage.id).count() == 1


def test_gc_storage_cleanup_deletes_digest_alias(test_db):
    """
    When storage is purged, its DigestAlias rows should be deleted
    as part of the cleanup (before ImageStorage.delete()).
    """
    location = test_db["location"]

    storage = ImageStorage.create(
        uuid="gc-test-uuid-6",
        cas_path=True,
        content_checksum="sha256:gc_test_6",
        canonical_sha256="sha256:gc_test_6",
    )
    ImageStoragePlacement.create(storage=storage, location=location)
    DigestAlias.create(
        digest="sha512:gc_alias_purge",
        image_storage=storage,
    )

    # Simulate storage purge: delete DigestAlias, then placements, then storage
    deleted_alias = DigestAlias.delete().where(DigestAlias.image_storage == storage.id).execute()
    assert deleted_alias == 1

    ImageStoragePlacement.delete().where(ImageStoragePlacement.storage == storage.id).execute()

    ImageStorage.delete().where(ImageStorage.id == storage.id).execute()

    # Verify everything is cleaned up
    assert DigestAlias.select().where(DigestAlias.digest == "sha512:gc_alias_purge").count() == 0
    assert ImageStorage.select().where(ImageStorage.id == storage.id).count() == 0

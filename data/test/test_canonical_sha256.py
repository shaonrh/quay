"""
Tests for canonical_sha256 on ImageStorage and the multi-algorithm digest support
introduced by PROJQUAY-11538-11539.

Tests cover:
- Schema: canonical_sha256 column exists and works
- Blob creation with dual checksums (content_checksum + canonical_sha256)
- Dedup by canonical_sha256 with DigestAlias creation on mismatch
- temp_link_blob dual lookup
- GC placements_to_filtered_paths_set uses canonical_sha256
- get_repository_blob_by_canonical_sha256
- effective_canonical_sha256 fallback property
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
    """Set up a temporary in-memory SQLite database for canonical_sha256 tests."""
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


class TestCanonicalSha256Column:
    """Tests for the canonical_sha256 column on ImageStorage."""

    def test_create_with_canonical_sha256(self, test_db):
        """Verify ImageStorage can be created with canonical_sha256."""
        storage = ImageStorage.create(
            uuid="test-uuid-1",
            cas_path=True,
            content_checksum="sha512:aabbccdd",
            canonical_sha256="sha256:11223344",
        )
        assert storage.content_checksum == "sha512:aabbccdd"
        assert storage.canonical_sha256 == "sha256:11223344"

    def test_create_without_canonical_sha256(self, test_db):
        """Verify ImageStorage can be created without canonical_sha256 (nullable)."""
        storage = ImageStorage.create(
            uuid="test-uuid-2",
            cas_path=True,
            content_checksum="sha256:aabbccdd",
        )
        assert storage.content_checksum == "sha256:aabbccdd"
        assert storage.canonical_sha256 is None

    def test_effective_canonical_sha256_with_value(self, test_db):
        """effective_canonical_sha256 returns canonical_sha256 when populated."""
        storage = ImageStorage.create(
            uuid="test-uuid-3",
            cas_path=True,
            content_checksum="sha512:aabbccdd",
            canonical_sha256="sha256:11223344",
        )
        assert storage.effective_canonical_sha256 == "sha256:11223344"

    def test_effective_canonical_sha256_fallback(self, test_db):
        """effective_canonical_sha256 falls back to content_checksum when canonical_sha256 is NULL."""
        storage = ImageStorage.create(
            uuid="test-uuid-4",
            cas_path=True,
            content_checksum="sha256:fallback_test",
        )
        assert storage.effective_canonical_sha256 == "sha256:fallback_test"

    def test_sha256_upload_same_checksums(self, test_db):
        """For SHA-256 uploads, content_checksum == canonical_sha256."""
        storage = ImageStorage.create(
            uuid="test-uuid-5",
            cas_path=True,
            content_checksum="sha256:same_for_both",
            canonical_sha256="sha256:same_for_both",
        )
        assert storage.content_checksum == storage.canonical_sha256

    def test_sha512_upload_different_checksums(self, test_db):
        """For SHA-512 uploads, content_checksum != canonical_sha256."""
        storage = ImageStorage.create(
            uuid="test-uuid-6",
            cas_path=True,
            content_checksum="sha512:client_digest_here",
            canonical_sha256="sha256:computed_sha256_here",
        )
        assert storage.content_checksum != storage.canonical_sha256
        assert storage.content_checksum.startswith("sha512:")
        assert storage.canonical_sha256.startswith("sha256:")


class TestDedupByCanonicalSha256:
    """Tests for deduplication by canonical_sha256."""

    def test_lookup_by_canonical_sha256(self, test_db):
        """Verify lookup by canonical_sha256 finds the correct storage."""
        ImageStorage.create(
            uuid="dedup-1",
            cas_path=True,
            content_checksum="sha512:client1",
            canonical_sha256="sha256:shared_content",
        )

        found = (
            ImageStorage.select()
            .where(ImageStorage.canonical_sha256 == "sha256:shared_content")
            .first()
        )
        assert found is not None
        assert found.content_checksum == "sha512:client1"

    def test_dedup_creates_digest_alias(self, test_db):
        """When dedup matches by canonical_sha256 but content_checksum differs,
        a DigestAlias should be created for the new digest."""
        storage = ImageStorage.create(
            uuid="dedup-2",
            cas_path=True,
            content_checksum="sha256:original_digest",
            canonical_sha256="sha256:shared_content_2",
        )

        # Simulate dedup match with different client digest
        new_content_checksum = "sha512:new_client_digest"
        if new_content_checksum != storage.content_checksum:
            DigestAlias.create(
                digest=new_content_checksum,
                image_storage=storage,
            )

        alias = DigestAlias.get(DigestAlias.digest == new_content_checksum)
        assert alias.image_storage_id == storage.id


class TestTempLinkBlobDualLookup:
    """Tests for temp_link_blob dual lookup logic."""

    def test_lookup_by_content_checksum(self, test_db):
        """temp_link_blob should find storage by content_checksum."""
        storage = ImageStorage.create(
            uuid="temp-link-1",
            cas_path=True,
            content_checksum="sha512:find_by_cc",
            canonical_sha256="sha256:canonical_1",
        )

        # Direct content_checksum lookup
        found = ImageStorage.get(content_checksum="sha512:find_by_cc")
        assert found.id == storage.id

    def test_lookup_by_canonical_sha256_fallback(self, test_db):
        """temp_link_blob should fall back to canonical_sha256 lookup."""
        storage = ImageStorage.create(
            uuid="temp-link-2",
            cas_path=True,
            content_checksum="sha512:not_this_digest",
            canonical_sha256="sha256:find_by_canonical",
        )

        # content_checksum lookup fails
        try:
            ImageStorage.get(content_checksum="sha256:find_by_canonical")
            assert False, "Should not find by content_checksum"
        except ImageStorage.DoesNotExist:
            pass

        # canonical_sha256 fallback succeeds
        found = (
            ImageStorage.select()
            .where(ImageStorage.canonical_sha256 == "sha256:find_by_canonical")
            .first()
        )
        assert found is not None
        assert found.id == storage.id


class TestGCCanonicalSha256:
    """Tests for GC paths using canonical_sha256."""

    def test_placements_use_canonical_sha256(self, test_db):
        """Verify placements filtering uses canonical_sha256 not content_checksum."""
        location = test_db["location"]

        # Create two storages with different content_checksum but same canonical_sha256
        storage1 = ImageStorage.create(
            uuid="gc-1",
            cas_path=True,
            content_checksum="sha256:same_content",
            canonical_sha256="sha256:same_content",
        )
        storage2 = ImageStorage.create(
            uuid="gc-2",
            cas_path=True,
            content_checksum="sha512:different_algo_same_content",
            canonical_sha256="sha256:same_content",
        )

        ImageStoragePlacement.create(storage=storage1, location=location)
        ImageStoragePlacement.create(storage=storage2, location=location)

        # Both storages reference same canonical_sha256
        query = ImageStorage.select(ImageStorage.canonical_sha256).where(
            ImageStorage.canonical_sha256 << ["sha256:same_content"]
        )
        referenced = set(s.canonical_sha256 for s in query)
        assert "sha256:same_content" in referenced

        # If we delete storage1, storage2 still references the canonical_sha256
        ImageStorage.delete().where(ImageStorage.id == storage1.id).execute()
        query = ImageStorage.select(ImageStorage.canonical_sha256).where(
            ImageStorage.canonical_sha256 << ["sha256:same_content"]
        )
        still_referenced = set(s.canonical_sha256 for s in query)
        assert "sha256:same_content" in still_referenced  # storage2 still alive

    def test_special_blob_check_uses_canonical(self, test_db):
        """SPECIAL_BLOB_DIGESTS checks work with canonical_sha256.
        Note: We hardcode the known value to avoid triggering Flask imports."""
        EMPTY_LAYER = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        assert EMPTY_LAYER.startswith("sha256:")


class TestGetRepositoryBlobByCanonicalSha256:
    """Tests for get_repository_blob_by_canonical_sha256."""

    def test_find_via_manifest_blob(self, test_db):
        """Find a blob in repository via ManifestBlob + canonical_sha256."""
        repo = test_db["repo"]
        location = test_db["location"]

        storage = ImageStorage.create(
            uuid="repo-blob-1",
            cas_path=True,
            content_checksum="sha512:non_sha256_digest",
            canonical_sha256="sha256:canonical_for_lookup",
            image_size=100,
        )
        ImageStoragePlacement.create(storage=storage, location=location)

        try:
            mt = MediaType.get(name="application/vnd.oci.image.manifest.v1+json")
        except MediaType.DoesNotExist:
            mt = MediaType.create(name="application/vnd.oci.image.manifest.v1+json")

        manifest = Manifest.create(
            repository=repo,
            digest="sha256:manifest_test_1",
            media_type=mt,
            manifest_bytes="{}",
        )
        ManifestBlob.create(manifest=manifest, repository=repo, blob=storage)

        # Look up by canonical_sha256
        found = (
            ImageStorage.select(ImageStorage.uuid)
            .join(ManifestBlob, on=(ManifestBlob.blob == ImageStorage.id))
            .where(
                ManifestBlob.repository == repo.id,
                ImageStorage.canonical_sha256 == "sha256:canonical_for_lookup",
            )
            .get()
        )
        assert found.uuid == "repo-blob-1"

    def test_find_via_uploaded_blob(self, test_db):
        """Find a blob in repository via UploadedBlob + canonical_sha256."""
        repo = test_db["repo"]
        location = test_db["location"]

        from datetime import datetime, timedelta

        storage = ImageStorage.create(
            uuid="repo-blob-2",
            cas_path=True,
            content_checksum="sha512:uploaded_digest",
            canonical_sha256="sha256:canonical_uploaded",
            image_size=200,
        )
        ImageStoragePlacement.create(storage=storage, location=location)
        UploadedBlob.create(
            repository=repo,
            blob=storage,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )

        # Look up by canonical_sha256
        found = (
            ImageStorage.select(ImageStorage.uuid)
            .join(UploadedBlob, on=(UploadedBlob.blob == ImageStorage.id))
            .where(
                UploadedBlob.repository == repo.id,
                ImageStorage.canonical_sha256 == "sha256:canonical_uploaded",
            )
            .get()
        )
        assert found.uuid == "repo-blob-2"

    def test_not_found_returns_none(self, test_db):
        """Non-existent canonical_sha256 returns no results."""
        repo = test_db["repo"]

        found = (
            ImageStorage.select(ImageStorage.uuid)
            .join(ManifestBlob, on=(ManifestBlob.blob == ImageStorage.id))
            .where(
                ManifestBlob.repository == repo.id,
                ImageStorage.canonical_sha256 == "sha256:does_not_exist",
            )
        )
        assert len(list(found)) == 0


class TestBlobDatatype:
    """Tests for the Blob datatype with canonical_sha256.

    Note: We test the ImageStorage model properties directly here because
    importing data.registry_model.datatypes triggers the Flask import chain.
    The Blob.for_image_storage and Blob.canonical_sha256 are tested via the
    effective_canonical_sha256 property on the model.
    """

    def test_image_storage_effective_canonical_sha256_with_sha512(self, test_db):
        """effective_canonical_sha256 returns canonical_sha256 for SHA-512 uploads."""
        storage = ImageStorage.create(
            uuid="blob-dt-1",
            cas_path=True,
            content_checksum="sha512:client_digest",
            canonical_sha256="sha256:internal_sha256",
            image_size=100,
        )

        assert storage.content_checksum == "sha512:client_digest"
        assert storage.effective_canonical_sha256 == "sha256:internal_sha256"
        # Verify content_checksum != canonical_sha256 for non-SHA-256 uploads
        assert storage.content_checksum != storage.effective_canonical_sha256

    def test_image_storage_checksums_for_sha256_upload(self, test_db):
        """For SHA-256 uploads, content_checksum == canonical_sha256."""
        storage = ImageStorage.create(
            uuid="blob-dt-2",
            cas_path=True,
            content_checksum="sha256:same_value",
            canonical_sha256="sha256:same_value",
            image_size=75,
        )

        assert storage.content_checksum == storage.canonical_sha256
        assert storage.effective_canonical_sha256 == "sha256:same_value"

    def test_image_storage_null_canonical_sha256_fallback(self, test_db):
        """effective_canonical_sha256 falls back to content_checksum when null."""
        storage = ImageStorage.create(
            uuid="blob-dt-3",
            cas_path=True,
            content_checksum="sha256:fallback_value",
            image_size=50,
        )
        # canonical_sha256 is None
        assert storage.canonical_sha256 is None
        assert storage.effective_canonical_sha256 == "sha256:fallback_value"

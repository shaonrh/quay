import hashlib
import os
import tarfile
from contextlib import closing
from io import BytesIO

import pytest

from data.registry_model.blobuploader import (
    BlobDigestMismatchException,
    BlobTooLargeException,
    BlobUploadException,
    BlobUploadSettings,
    retrieve_blob_upload_manager,
    upload_blob,
)
from data.registry_model.registry_oci_model import OCIModel
from storage.distributedstorage import DistributedStorage
from storage.fakestorage import FakeStorage
from test.fixtures import *


@pytest.fixture()
def registry_model(initialized_db):
    return OCIModel()


@pytest.mark.parametrize(
    "chunk_count",
    [
        0,
        1,
        2,
        10,
    ],
)
@pytest.mark.parametrize(
    "subchunk",
    [
        True,
        False,
    ],
)
def test_basic_upload_blob(chunk_count, subchunk, registry_model):
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {"TESTING": True}

    data = b""
    with upload_blob(repository_ref, storage, settings) as manager:
        assert manager
        assert manager.blob_upload_id

        for index in range(0, chunk_count):
            chunk_data = os.urandom(100)
            data += chunk_data

            if subchunk:
                manager.upload_chunk(app_config, BytesIO(chunk_data))
                manager.upload_chunk(app_config, BytesIO(chunk_data), (index * 100) + 50)
            else:
                manager.upload_chunk(app_config, BytesIO(chunk_data))

        blob = manager.commit_to_blob(app_config)

    # Check the blob.
    assert blob.compressed_size == len(data)
    assert blob.digest == "sha256:" + hashlib.sha256(data).hexdigest()

    # Ensure the blob exists in storage and has the expected data.
    assert storage.get_content(["local_us"], blob.storage_path) == data


def test_cancel_upload(registry_model):
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {"TESTING": True}

    blob_upload_id = None
    with upload_blob(repository_ref, storage, settings) as manager:
        blob_upload_id = manager.blob_upload_id
        assert registry_model.lookup_blob_upload(repository_ref, blob_upload_id) is not None

        manager.upload_chunk(app_config, BytesIO(b"hello world"))

    # Since the blob was not comitted, the upload should be deleted.
    assert blob_upload_id
    assert registry_model.lookup_blob_upload(repository_ref, blob_upload_id) is None


def test_too_large(registry_model):
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("1K", 3600)
    app_config = {"TESTING": True}

    with upload_blob(repository_ref, storage, settings) as manager:
        with pytest.raises(BlobTooLargeException):
            manager.upload_chunk(app_config, BytesIO(os.urandom(1024 * 1024 * 2)))


def test_extra_blob_stream_handlers(registry_model):
    handler1_result = []
    handler2_result = []

    def handler1(bytes_data):
        handler1_result.append(bytes_data)

    def handler2(bytes_data):
        handler2_result.append(bytes_data)

    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("1K", 3600)
    app_config = {"TESTING": True}

    with upload_blob(
        repository_ref, storage, settings, extra_blob_stream_handlers=[handler1, handler2]
    ) as manager:
        manager.upload_chunk(app_config, BytesIO(b"hello "))
        manager.upload_chunk(app_config, BytesIO(b"world"))

    assert b"".join(handler1_result) == b"hello world"
    assert b"".join(handler2_result) == b"hello world"


def valid_tar_gz(contents):
    assert isinstance(contents, bytes)
    with closing(BytesIO()) as layer_data:
        with closing(tarfile.open(fileobj=layer_data, mode="w|gz")) as tar_file:
            tar_file_info = tarfile.TarInfo(name="somefile")
            tar_file_info.type = tarfile.REGTYPE
            tar_file_info.size = len(contents)
            tar_file_info.mtime = 1
            tar_file.addfile(tar_file_info, BytesIO(contents))

        layer_bytes = layer_data.getvalue()
    return layer_bytes


def test_uncompressed_size(registry_model):
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("1K", 3600)
    app_config = {"TESTING": True}

    with upload_blob(repository_ref, storage, settings) as manager:
        manager.upload_chunk(app_config, BytesIO(valid_tar_gz(b"hello world")))

        blob = manager.commit_to_blob(app_config)

    assert blob.compressed_size is not None
    assert blob.uncompressed_size is not None


def test_monolithic_upload_with_sha512_digest(registry_model):
    """Upload blob and finalize with digest=sha512:... — on-demand validation via read-back."""
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {
        "TESTING": True,
        "FEATURE_MULTI_ALGORITHM_SUPPORT": True,
        "ALLOWED_HASH_ALGORITHMS": ["sha256", "sha512"],
    }

    data = os.urandom(256)
    expected_sha512 = "sha512:" + hashlib.sha512(data).hexdigest()
    expected_sha256 = "sha256:" + hashlib.sha256(data).hexdigest()

    with upload_blob(repository_ref, storage, settings) as manager:
        manager.upload_chunk(app_config, BytesIO(data))
        blob = manager.commit_to_blob(app_config, expected_digest=expected_sha512)

    # Blob committed successfully
    assert blob is not None
    # Storage path is SHA-256-based (canonical)
    assert storage.get_content(["local_us"], blob.storage_path) == data
    # Digest on the blob object is the canonical SHA-256
    assert blob.digest == expected_sha256


def test_chunked_upload_with_sha512_finalization(registry_model):
    """Multi-chunk upload finalized with sha512 — read-back validates across chunks."""
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {
        "TESTING": True,
        "FEATURE_MULTI_ALGORITHM_SUPPORT": True,
        "ALLOWED_HASH_ALGORITHMS": ["sha256", "sha512"],
    }

    chunks = [os.urandom(100) for _ in range(5)]
    full_data = b"".join(chunks)
    expected_sha512 = "sha512:" + hashlib.sha512(full_data).hexdigest()

    with upload_blob(repository_ref, storage, settings) as manager:
        for chunk in chunks:
            manager.upload_chunk(app_config, BytesIO(chunk))
        blob = manager.commit_to_blob(app_config, expected_digest=expected_sha512)

    assert blob is not None
    assert storage.get_content(["local_us"], blob.storage_path) == full_data


def test_sha512_digest_mismatch(registry_model):
    """Wrong sha512 digest raises BlobDigestMismatchException."""
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {
        "TESTING": True,
        "FEATURE_MULTI_ALGORITHM_SUPPORT": True,
        "ALLOWED_HASH_ALGORITHMS": ["sha256", "sha512"],
    }

    data = os.urandom(256)
    wrong_sha512 = "sha512:" + hashlib.sha512(b"wrong data").hexdigest()

    with upload_blob(repository_ref, storage, settings) as manager:
        manager.upload_chunk(app_config, BytesIO(data))
        with pytest.raises(BlobDigestMismatchException):
            manager.commit_to_blob(app_config, expected_digest=wrong_sha512)


def test_non_sha256_rejected_when_feature_disabled(registry_model):
    """Non-SHA-256 digest rejected when FEATURE_MULTI_ALGORITHM_SUPPORT is disabled."""
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {
        "TESTING": True,
        "FEATURE_MULTI_ALGORITHM_SUPPORT": False,
    }

    data = os.urandom(256)
    sha512_digest = "sha512:" + hashlib.sha512(data).hexdigest()

    with upload_blob(repository_ref, storage, settings) as manager:
        manager.upload_chunk(app_config, BytesIO(data))
        with pytest.raises(BlobDigestMismatchException):
            manager.commit_to_blob(app_config, expected_digest=sha512_digest)


def test_sha256_upload_no_readback(registry_model):
    """Standard SHA-256 upload does not trigger storage read-back — fast path unchanged."""
    repository_ref = registry_model.lookup_repository("devtable", "complex")
    storage = DistributedStorage({"local_us": FakeStorage(None)}, ["local_us"])
    settings = BlobUploadSettings("2M", 3600)
    app_config = {"TESTING": True}

    data = os.urandom(256)
    expected_sha256 = "sha256:" + hashlib.sha256(data).hexdigest()

    with upload_blob(repository_ref, storage, settings) as manager:
        manager.upload_chunk(app_config, BytesIO(data))
        blob = manager.commit_to_blob(app_config, expected_digest=expected_sha256)

    assert blob is not None
    assert blob.digest == expected_sha256
    assert storage.get_content(["local_us"], blob.storage_path) == data

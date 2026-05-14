import hashlib
import logging
import time
from collections import namedtuple
from contextlib import contextmanager

import bitmath
from prometheus_client import Counter, Histogram

from data.database import CloseForLongOperation, db_transaction
from data.registry_model import registry_model
from digest import digest_tools
from util.registry.filelike import StreamSlice, wrap_with_handler
from util.registry.gzipstream import calculate_size_handler

logger = logging.getLogger(__name__)


chunk_upload_duration = Histogram(
    "quay_chunk_upload_duration_seconds",
    "number of seconds for a chunk to be uploaded to the registry",
    labelnames=["region"],
)
pushed_bytes_total = Counter(
    "quay_registry_image_pushed_bytes_total", "number of bytes pushed to the registry"
)


BLOB_CONTENT_TYPE = "application/octet-stream"


class BlobUploadException(Exception):
    """
    Base for all exceptions raised when uploading blobs.
    """


class BlobRangeMismatchException(BlobUploadException):
    """
    Exception raised if the range to be uploaded does not match.
    """


class BlobDigestMismatchException(BlobUploadException):
    """
    Exception raised if the digest requested does not match that of the contents uploaded.
    """


class BlobTooLargeException(BlobUploadException):
    """
    Exception raised if the data uploaded exceeds the maximum_blob_size.
    """

    def __init__(self, uploaded, max_allowed):
        super(BlobTooLargeException, self).__init__()
        self.uploaded = uploaded
        self.max_allowed = max_allowed


BlobUploadSettings = namedtuple(
    "BlobUploadSettings",
    ["maximum_blob_size", "committed_blob_expiration"],
)


def create_blob_upload(repository_ref, storage, settings, extra_blob_stream_handlers=None):
    """
    Creates a new blob upload in the specified repository and returns a manager for interacting with
    that upload.

    Returns None if a new blob upload could not be started.
    """
    location_name = storage.preferred_locations[0]
    new_upload_uuid, upload_metadata = storage.initiate_chunked_upload(location_name)
    blob_upload = registry_model.create_blob_upload(
        repository_ref, new_upload_uuid, location_name, upload_metadata
    )
    if blob_upload is None:
        return None

    return _BlobUploadManager(
        repository_ref, blob_upload, settings, storage, extra_blob_stream_handlers
    )


def retrieve_blob_upload_manager(repository_ref, blob_upload_id, storage, settings):
    """
    Retrieves the manager for an in-progress blob upload with the specified ID under the given
    repository or None if none.
    """
    blob_upload = registry_model.lookup_blob_upload(repository_ref, blob_upload_id)
    if blob_upload is None:
        return None

    return _BlobUploadManager(repository_ref, blob_upload, settings, storage)


@contextmanager
def complete_when_uploaded(blob_upload):
    """
    Wraps the given blob upload in a context manager that completes the upload when the context
    closes.
    """
    try:
        yield blob_upload
    except Exception as ex:
        logger.exception("Exception when uploading blob `%s`", blob_upload.blob_upload_id)
        raise ex
    finally:
        # Cancel the upload if something went wrong or it was not commit to a blob.
        if blob_upload.committed_blob is None:
            blob_upload.cancel_upload()


@contextmanager
def upload_blob(repository_ref, storage, settings, extra_blob_stream_handlers=None):
    """
    Starts a new blob upload in the specified repository and yields a manager for interacting with
    that upload.

    When the context manager completes, the blob upload is deleted, whether committed to a blob or
    not. Yields None if a blob upload could not be started.
    """
    assert repository_ref is not None

    created = create_blob_upload(repository_ref, storage, settings, extra_blob_stream_handlers)
    if not created:
        yield None
        return

    try:
        yield created
    except Exception as ex:
        logger.exception("Exception when uploading blob `%s`", created.blob_upload_id)
        raise ex
    finally:
        # Cancel the upload if something went wrong or it was not commit to a blob.
        if created.committed_blob is None:
            created.cancel_upload()


class _BlobUploadManager(object):
    """
    Defines a helper class for easily interacting with blob uploads in progress, including handling
    of database and storage calls.
    """

    def __init__(
        self, repository_ref, blob_upload, settings, storage, extra_blob_stream_handlers=None
    ):
        assert repository_ref is not None
        assert blob_upload is not None

        self.repository_ref = repository_ref
        self.blob_upload = blob_upload
        self.settings = settings
        self.storage = storage
        self.extra_blob_stream_handlers = extra_blob_stream_handlers
        self.committed_blob = None

    @property
    def blob_upload_id(self):
        """
        Returns the unique ID for the blob upload.
        """
        return self.blob_upload.upload_id

    def upload_chunk(self, app_config, input_fp, start_offset=0, length=-1):
        """
        Uploads a chunk of data found in the given input file-like interface. start_offset and
        length are optional and should match a range header if any was given.

        Returns the total number of bytes uploaded after this upload has completed. Raises a
        BlobUploadException if the upload failed.
        """
        assert start_offset is not None
        assert length is not None

        if start_offset > 0 and start_offset > self.blob_upload.byte_count:
            logger.error("start_offset provided greater than blob_upload.byte_count")
            raise BlobRangeMismatchException()

        # Ensure that we won't go over the allowed maximum size for blobs.
        max_blob_size = bitmath.parse_string_unsafe(self.settings.maximum_blob_size)
        uploaded = bitmath.Byte(length + start_offset)
        if length > -1 and uploaded > max_blob_size:
            raise BlobTooLargeException(uploaded=uploaded.bytes, max_allowed=max_blob_size.bytes)

        location_set = {self.blob_upload.location_name}
        upload_error = None
        with CloseForLongOperation(app_config):
            if start_offset > 0 and start_offset < self.blob_upload.byte_count:
                # Skip the bytes which were received on a previous push, which are already stored and
                # included in the sha calculation
                overlap_size = self.blob_upload.byte_count - start_offset
                input_fp = StreamSlice(input_fp, overlap_size)

                # Update our upload bounds to reflect the skipped portion of the overlap
                start_offset = self.blob_upload.byte_count
                length = max(length - overlap_size, 0)

            # We use this to escape early in case we have already processed all of the bytes the user
            # wants to upload.
            if length == 0:
                return self.blob_upload.byte_count

            # SHA-256 is always computed during upload for storage paths, dedup, and GC.
            # Non-SHA-256 hashes are only computed on-demand at finalization when the
            # client explicitly provides a non-SHA-256 digest.
            input_fp = wrap_with_handler(input_fp, self.blob_upload.sha_state.update)

            if self.extra_blob_stream_handlers:
                for handler in self.extra_blob_stream_handlers:
                    input_fp = wrap_with_handler(input_fp, handler)

            # If this is the first chunk and we're starting at the 0 offset, add a handler to gunzip the
            # stream so we can determine the uncompressed size. We'll throw out this data if another chunk
            # comes in, but in the common case the docker client only sends one chunk.
            size_info = None
            if start_offset == 0 and self.blob_upload.chunk_count == 0:
                size_info, fn = calculate_size_handler()
                input_fp = wrap_with_handler(input_fp, fn)

            start_time = time.time()
            length_written, new_metadata, upload_error = self.storage.stream_upload_chunk(
                location_set,
                self.blob_upload.upload_id,
                start_offset,
                length,
                input_fp,
                self.blob_upload.storage_metadata,
                content_type=BLOB_CONTENT_TYPE,
            )

            if upload_error is not None:
                logger.error("storage.stream_upload_chunk returned error %s", upload_error)
                raise BlobUploadException(upload_error)

            # Update the chunk upload time and push bytes metrics.
            chunk_upload_duration.labels(list(location_set)[0]).observe(time.time() - start_time)
            pushed_bytes_total.inc(length_written)
            logger.debug(
                f"Uploaded {length_written} bytes to blob {self.blob_upload.upload_id} "
                f"took {time.time() - start_time} seconds"
            )

        # Ensure we have not gone beyond the max layer size.
        new_blob_bytes = self.blob_upload.byte_count + length_written
        new_blob_size = bitmath.Byte(new_blob_bytes)
        if new_blob_size > max_blob_size:
            raise BlobTooLargeException(uploaded=new_blob_size, max_allowed=max_blob_size.bytes)

        # If we determined an uncompressed size and this is the first chunk, add it to the blob.
        # Otherwise, we clear the size from the blob as it was uploaded in multiple chunks.
        uncompressed_byte_count = self.blob_upload.uncompressed_byte_count
        if size_info is not None and self.blob_upload.chunk_count == 0 and size_info.is_valid:
            uncompressed_byte_count = size_info.uncompressed_size
        elif length_written > 0:
            # Otherwise, if we wrote some bytes and the above conditions were not met, then we don't
            # know the uncompressed size.
            uncompressed_byte_count = None

        self.blob_upload = registry_model.update_blob_upload(
            self.blob_upload,
            uncompressed_byte_count,
            new_metadata,
            new_blob_bytes,
            self.blob_upload.chunk_count + 1,
            self.blob_upload.sha_state,
        )
        if self.blob_upload is None:
            raise BlobUploadException("Could not complete upload of chunk")

        return new_blob_bytes

    def cancel_upload(self):
        """
        Cancels the blob upload, deleting any data uploaded and removing the upload itself.
        """
        if self.blob_upload is None:
            return

        # Tell storage to cancel the chunked upload, deleting its contents.
        self.storage.cancel_chunked_upload(
            {self.blob_upload.location_name},
            self.blob_upload.upload_id,
            self.blob_upload.storage_metadata,
        )

        # Remove the blob upload record itself.
        registry_model.delete_blob_upload(self.blob_upload)

    def commit_to_blob(self, app_config, expected_digest=None):
        """
        Commits the blob upload to a blob under the repository. The resulting blob will be marked to
        not be GCed for some period of time (as configured by `committed_blob_expiration`).

        For SHA-256 digests, validation happens before finalization using the in-memory sha_state.
        For non-SHA-256 digests, the blob is finalized first, then read back from storage to
        compute and validate the requested hash on-demand.
        """
        client_digest_str = None
        parsed_digest = None

        if expected_digest is not None:
            multi_algo_enabled = app_config.get("FEATURE_MULTI_ALGORITHM_SUPPORT", False)
            parsed_digest = digest_tools.Digest.parse_digest(expected_digest)

            if parsed_digest.hash_alg != "sha256" and not multi_algo_enabled:
                raise BlobDigestMismatchException()

            if parsed_digest.hash_alg == "sha256":
                # Standard SHA-256 validation before finalization (existing fast path)
                self._validate_digest(expected_digest)
            else:
                # Non-SHA-256: will validate after finalization via storage read-back
                client_digest_str = expected_digest

        # Finalize the storage (uses SHA-256 for storage path -- unchanged)
        storage_already_existed = self._finalize_blob_storage(app_config)

        # Compute the canonical SHA-256 digest (always from sha_state)
        canonical_sha256 = digest_tools.sha256_digest_from_hashlib(self.blob_upload.sha_state)

        # If client provided non-SHA-256 digest, read blob back and verify on-demand
        if client_digest_str is not None:
            self._validate_digest_from_storage(
                canonical_sha256, parsed_digest.hash_alg, expected_digest, app_config
            )

        # content_checksum = client's digest if non-SHA-256, otherwise SHA-256
        content_checksum = client_digest_str if client_digest_str else canonical_sha256

        with db_transaction():
            blob = registry_model.commit_blob_upload(
                self.blob_upload,
                content_checksum,
                canonical_sha256,
                self.settings.committed_blob_expiration,
            )
            if blob is None:
                return None

        self.committed_blob = blob
        return blob

    def _validate_digest(self, expected_digest):
        """
        Verifies that the digest's SHA matches that of the uploaded data.
        """
        try:
            computed_digest = digest_tools.sha256_digest_from_hashlib(self.blob_upload.sha_state)
            if not digest_tools.digests_equal(computed_digest, expected_digest):
                logger.error(
                    "Digest mismatch for upload %s: Expected digest %s, found digest %s",
                    self.blob_upload.upload_id,
                    expected_digest,
                    computed_digest,
                )
                raise BlobDigestMismatchException()
        except digest_tools.InvalidDigestException:
            raise BlobDigestMismatchException()

    def _validate_digest_from_storage(
        self, canonical_sha256, hash_alg, expected_digest, app_config
    ):
        """
        Validates a non-SHA-256 digest by reading the blob back from its final
        storage location and computing the requested hash on-the-fly.

        Only called for non-SHA-256 digests (rare path). The blob must already be
        at its final content-addressed path (_finalize_blob_storage() must have
        been called first).
        """
        try:
            hashlib_name = hash_alg.replace("-", "_")
            hasher = hashlib.new(hashlib_name)
        except ValueError:
            logger.error(
                "Unsupported hash algorithm %s for upload %s",
                hash_alg,
                self.blob_upload.upload_id,
            )
            raise BlobDigestMismatchException()

        storage_path = digest_tools.content_path(canonical_sha256)
        location_set = {self.blob_upload.location_name}

        try:
            with CloseForLongOperation(app_config):
                for chunk in self.storage.stream_read(location_set, storage_path):
                    hasher.update(chunk)
        except IOError:
            logger.exception(
                "Failed to read blob from storage for digest validation: " "upload=%s, path=%s",
                self.blob_upload.upload_id,
                storage_path,
            )
            raise BlobDigestMismatchException()

        computed_digest = f"{hash_alg}:{hasher.hexdigest()}"
        if not digest_tools.digests_equal(computed_digest, expected_digest):
            logger.error(
                "Client digest mismatch for upload %s: Expected %s, computed %s",
                self.blob_upload.upload_id,
                expected_digest,
                computed_digest,
            )
            raise BlobDigestMismatchException()

    def _finalize_blob_storage(self, app_config):
        """
        When an upload is successful, this ends the uploading process from the storage's
        perspective.

        Returns True if the blob already existed.
        """
        computed_digest = digest_tools.sha256_digest_from_hashlib(self.blob_upload.sha_state)
        final_blob_location = digest_tools.content_path(computed_digest)

        # Close the database connection before we perform this operation, as it can take a while
        # and we shouldn't hold the connection during that time.
        with CloseForLongOperation(app_config):
            # Move the storage into place, or if this was a re-upload, cancel it
            already_existed = self.storage.exists(
                {self.blob_upload.location_name}, final_blob_location
            )
            if already_existed:
                # It already existed, clean up our upload which served as proof that the
                # uploader had the blob.
                self.storage.cancel_chunked_upload(
                    {self.blob_upload.location_name},
                    self.blob_upload.upload_id,
                    self.blob_upload.storage_metadata,
                )
            else:
                # We were the first ones to upload this image (at least to this location)
                # Let's copy it into place
                start_time = time.time()
                self.storage.complete_chunked_upload(
                    {self.blob_upload.location_name},
                    self.blob_upload.upload_id,
                    final_blob_location,
                    self.blob_upload.storage_metadata,
                )
                logger.debug(
                    f"Completed chunked upload for blob "
                    f"{self.blob_upload.upload_id} with digest {computed_digest} "
                    f"took {time.time() - start_time} seconds"
                )

        return already_existed

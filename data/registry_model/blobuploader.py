import base64
import json
import logging
import pickle
import time
from collections import namedtuple
from contextlib import contextmanager

import bitmath
from prometheus_client import Counter, Histogram

from data.database import CloseForLongOperation, db_transaction
from data.fields import safe_unpickle
from data.registry_model import registry_model
from digest import digest_tools
from util.registry.filelike import StreamSlice, wrap_with_handler
from util.registry.gzipstream import calculate_size_handler

logger = logging.getLogger(__name__)

# Deferred import of resumablehash to avoid breaking all uploads
# if the library is missing when the feature is disabled.
_resumablehash = None


def _get_resumablehash():
    """Lazily import resumablehash. Returns the module or None if unavailable."""
    global _resumablehash
    if _resumablehash is None:
        try:
            import resumablehash

            _resumablehash = resumablehash
        except ImportError:
            logger.warning(
                "resumablehash library not available. "
                "Multi-algorithm digest support will not function."
            )
            _resumablehash = False  # Sentinel: tried and failed
    return _resumablehash if _resumablehash is not False else None


def _serialize_hash_state(hasher):
    """Serialize a resumablehash hasher to a base64 string for DB storage."""
    return base64.b64encode(pickle.dumps(hasher)).decode("ascii")


def _deserialize_hash_state(state_str):
    """Deserialize a resumablehash hasher from a base64 string via safe_unpickle."""
    data = base64.b64decode(state_str.encode("ascii"))
    return safe_unpickle(data)


def _get_speculative_algorithms(app_config):
    """
    Returns the set of non-SHA-256 algorithms from ALLOWED_HASH_ALGORITHMS
    that should be speculatively computed during chunk uploads.

    Returns an empty set if the feature is disabled or resumablehash is unavailable.
    """
    if not app_config.get("FEATURE_MULTI_ALGORITHM_SUPPORT", False):
        return set()

    rh = _get_resumablehash()
    if rh is None:
        return set()

    allowed = app_config.get("ALLOWED_HASH_ALGORITHMS", ["sha256"])
    # Filter to non-sha256 algorithms that resumablehash supports
    speculative = set()
    for algo in allowed:
        if algo != "sha256" and hasattr(rh, algo):
            speculative.add(algo)
    return speculative


def _create_hasher(algo_name):
    """Create a new resumablehash hasher for the given algorithm name."""
    rh = _get_resumablehash()
    if rh is None:
        return None
    constructor = getattr(rh, algo_name, None)
    if constructor is None:
        return None
    return constructor()


def _serialize_speculative_states(hashers_dict):
    """
    Serialize a dict of {algo_name: hasher} to a JSON string for DB storage.
    Each hasher is individually base64-pickled.
    """
    serialized = {}
    for algo, hasher in hashers_dict.items():
        serialized[algo] = _serialize_hash_state(hasher)
    return json.dumps(serialized)


def _deserialize_speculative_states(state_str):
    """
    Deserialize a JSON string back to a dict of {algo_name: hasher}.
    Returns an empty dict if state_str is None or empty.
    """
    if not state_str:
        return {}
    try:
        serialized = json.loads(state_str)
        result = {}
        for algo, encoded_state in serialized.items():
            try:
                result[algo] = _deserialize_hash_state(encoded_state)
            except Exception:
                logger.warning(
                    "Failed to deserialize hash state for algorithm %s, skipping",
                    algo,
                    exc_info=True,
                )
        return result
    except (json.JSONDecodeError, TypeError):
        # Fallback: might be a legacy single-state string; ignore it
        logger.warning("Failed to parse client_hash_state as JSON, treating as empty")
        return {}


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
        self._speculative_hashers = None

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

            # Determine which additional algorithms to hash speculatively.
            # For chunked uploads, the client's algorithm is unknown until PUT,
            # so we compute ALL algorithms in ALLOWED_HASH_ALGORITHMS during every chunk.
            speculative_hashers = {}
            try:
                speculative_algos = _get_speculative_algorithms(app_config)
                if speculative_algos:
                    # Try to restore from persisted state
                    speculative_hashers = _deserialize_speculative_states(
                        self.blob_upload.client_hash_state
                    )
                    # Create hashers for any algorithms not yet initialized
                    for algo in speculative_algos:
                        if algo not in speculative_hashers:
                            hasher = _create_hasher(algo)
                            if hasher is not None:
                                speculative_hashers[algo] = hasher
            except Exception:
                logger.warning(
                    "Failed to initialize speculative hashers for upload %s, "
                    "continuing with SHA-256 only",
                    self.blob_upload.upload_id,
                    exc_info=True,
                )
                speculative_hashers = {}

            input_fp = wrap_with_handler(input_fp, self.blob_upload.sha_state.update)

            # Wrap with all speculative hashers
            for _algo, hasher in speculative_hashers.items():
                input_fp = wrap_with_handler(input_fp, hasher.update)

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

        # Serialize speculative hash states for persistence
        serialized_client_hash_state = None
        if speculative_hashers:
            serialized_client_hash_state = _serialize_speculative_states(speculative_hashers)

        # Store speculative hashers for use in commit_to_blob() within
        # the same request (avoids redundant deserialization for monolithic uploads)
        self._speculative_hashers = speculative_hashers if speculative_hashers else None

        self.blob_upload = registry_model.update_blob_upload(
            self.blob_upload,
            uncompressed_byte_count,
            new_metadata,
            new_blob_bytes,
            self.blob_upload.chunk_count + 1,
            self.blob_upload.sha_state,
            client_hash_state=(
                serialized_client_hash_state
                if serialized_client_hash_state
                else self.blob_upload.client_hash_state
            ),
            client_hash_algorithm=self.blob_upload.client_hash_algorithm,
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

        If expected_digest is specified, validates the digest against the appropriate hash state
        (SHA-256 for standard uploads, client-algorithm for multi-algorithm uploads using
        speculatively computed hashes).
        """
        client_digest_str = None
        parsed_digest = None

        if expected_digest is not None:
            multi_algo_enabled = app_config.get("FEATURE_MULTI_ALGORITHM_SUPPORT", False)
            parsed_digest = digest_tools.Digest.parse_digest(expected_digest)

            if parsed_digest.hash_alg != "sha256" and not multi_algo_enabled:
                # Feature disabled but client sent non-SHA-256 digest
                raise BlobDigestMismatchException()

            if parsed_digest.hash_alg != "sha256" and multi_algo_enabled:
                # Validate against the speculatively computed client-algorithm hash
                self._validate_client_digest(expected_digest, parsed_digest.hash_alg)
                client_digest_str = expected_digest
            else:
                # Standard SHA-256 validation (existing behavior)
                self._validate_digest(expected_digest)

        # Finalize the storage (uses SHA-256 for storage path -- unchanged)
        storage_already_existed = self._finalize_blob_storage(app_config)

        # Compute the canonical SHA-256 digest (always from sha_state)
        canonical_sha256 = digest_tools.sha256_digest_from_hashlib(self.blob_upload.sha_state)

        # Determine what goes into content_checksum:
        # - If client provided non-SHA-256: use client's digest
        # - If client provided SHA-256 (or no digest): use SHA-256
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

    def _validate_client_digest(self, expected_digest, hash_alg):
        """
        Verifies the expected digest against the speculatively computed hash state
        for the given algorithm. Used when the client provided a non-SHA-256 digest.

        The hasher is retrieved from:
        1. In-memory cache (self._speculative_hashers) if available (monolithic upload)
        2. Deserialized from self.blob_upload.client_hash_state (chunked upload)
        """
        try:
            # Try in-memory cache first (set during upload_chunk in same request)
            client_hasher = None
            if self._speculative_hashers and hash_alg in self._speculative_hashers:
                client_hasher = self._speculative_hashers[hash_alg]
            elif self.blob_upload.client_hash_state:
                # Deserialize from DB state
                all_hashers = _deserialize_speculative_states(self.blob_upload.client_hash_state)
                client_hasher = all_hashers.get(hash_alg)

            if client_hasher is None:
                logger.error(
                    "No hash state found for algorithm %s on upload %s. "
                    "The algorithm may not have been in ALLOWED_HASH_ALGORITHMS "
                    "during chunk uploads.",
                    hash_alg,
                    self.blob_upload.upload_id,
                )
                raise BlobDigestMismatchException()

            computed_hex = client_hasher.hexdigest()
            computed_digest = f"{hash_alg}:{computed_hex}"

            if not digest_tools.digests_equal(computed_digest, expected_digest):
                logger.error(
                    "Client digest mismatch for upload %s: Expected %s, computed %s",
                    self.blob_upload.upload_id,
                    expected_digest,
                    computed_digest,
                )
                raise BlobDigestMismatchException()
        except BlobDigestMismatchException:
            raise
        except Exception:
            logger.exception(
                "Unexpected error validating client digest for upload %s",
                self.blob_upload.upload_id,
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

"""
Tests for multi-algorithm digest support in the blob upload pipeline.

Tests the on-demand hash computation approach: SHA-256 is always computed
during upload; non-SHA-256 hashes are computed by reading the blob back
from storage at finalization time, only when the client explicitly provides
a non-SHA-256 digest.

Also tests the safe_unpickle helper (used by ResumableSHAField for SHA-256
state persistence) and the digest_tools helpers.
"""

import hashlib
import os
import pickle

import pytest
import resumablehash

from data.fields import safe_unpickle


class TestSafeUnpickle:
    """Tests for the safe_unpickle public helper in data/fields.py."""

    def test_safe_unpickle_allowed_sha256(self):
        """Verify safe_unpickle succeeds for resumablehash.sha256."""
        h = resumablehash.sha256()
        h.update(b"hello")
        data = pickle.dumps(h)
        restored = safe_unpickle(data)
        assert restored.hexdigest() == h.hexdigest()

    def test_safe_unpickle_allowed_sha384(self):
        """Verify safe_unpickle succeeds for resumablehash.sha384."""
        h = resumablehash.sha384()
        h.update(b"hello")
        data = pickle.dumps(h)
        restored = safe_unpickle(data)
        assert restored.hexdigest() == h.hexdigest()

    def test_safe_unpickle_allowed_sha512(self):
        """Verify safe_unpickle succeeds for resumablehash.sha512."""
        h = resumablehash.sha512()
        h.update(b"hello")
        data = pickle.dumps(h)
        restored = safe_unpickle(data)
        assert restored.hexdigest() == h.hexdigest()

    def test_safe_unpickle_forbidden_classes(self):
        """Verify safe_unpickle raises UnpicklingError for arbitrary classes."""
        import io

        data = pickle.dumps(io.BytesIO(b"evil"))
        with pytest.raises(pickle.UnpicklingError):
            safe_unpickle(data)


class TestOnDemandHashComputation:
    """Tests for on-demand hash computation via hashlib streaming.

    These validate the approach used by _validate_digest_from_storage():
    read blob content in chunks and compute the hash using hashlib.
    """

    def test_streaming_sha512_matches_monolithic(self):
        """Streaming hashlib.sha512 over chunks matches all-at-once computation."""
        chunks = [os.urandom(100) for _ in range(10)]
        full_data = b"".join(chunks)

        # Streaming computation (mirrors _validate_digest_from_storage)
        hasher = hashlib.new("sha512")
        for chunk in chunks:
            hasher.update(chunk)

        expected = hashlib.sha512(full_data).hexdigest()
        assert hasher.hexdigest() == expected

    def test_streaming_sha384_matches_monolithic(self):
        """Streaming hashlib.sha384 over chunks matches all-at-once computation."""
        chunks = [os.urandom(100) for _ in range(10)]
        full_data = b"".join(chunks)

        hasher = hashlib.new("sha384")
        for chunk in chunks:
            hasher.update(chunk)

        expected = hashlib.sha384(full_data).hexdigest()
        assert hasher.hexdigest() == expected

    def test_oci_algorithm_name_mapping(self):
        """OCI algorithm names with dashes map correctly to hashlib names."""
        # OCI uses 'sha3-256', hashlib uses 'sha3_256'
        oci_name = "sha3-256"
        hashlib_name = oci_name.replace("-", "_")
        assert hashlib_name == "sha3_256"

        # Verify hashlib.new() accepts the mapped name
        h = hashlib.new(hashlib_name)
        h.update(b"test")
        assert len(h.hexdigest()) > 0

    def test_standard_algorithms_available(self):
        """Verify SHA-256, SHA-384, SHA-512 are available via hashlib.new()."""
        for algo in ["sha256", "sha384", "sha512"]:
            h = hashlib.new(algo)
            h.update(b"test data")
            assert len(h.hexdigest()) > 0

    def test_unsupported_algorithm_raises(self):
        """Unsupported algorithm name raises ValueError from hashlib.new()."""
        with pytest.raises(ValueError):
            hashlib.new("not_a_real_algorithm")

    def test_digest_string_format(self):
        """Computed digest strings match the expected 'algorithm:hex' format."""
        data = os.urandom(256)

        for algo in ["sha256", "sha384", "sha512"]:
            h = hashlib.new(algo)
            h.update(data)
            digest_str = f"{algo}:{h.hexdigest()}"
            assert digest_str.startswith(f"{algo}:")
            assert len(digest_str.split(":")) == 2


class TestDigestValidation:
    """Tests for digest validation logic."""

    def test_sha512_digest_computation(self):
        """Verify SHA-512 digest computed from resumablehash matches hashlib."""
        data = os.urandom(1024)
        rh_hasher = resumablehash.sha512()
        rh_hasher.update(data)
        expected = hashlib.sha512(data).hexdigest()
        assert rh_hasher.hexdigest() == expected

    def test_sha384_digest_computation(self):
        """Verify SHA-384 digest computed from resumablehash matches hashlib."""
        data = os.urandom(1024)
        rh_hasher = resumablehash.sha384()
        rh_hasher.update(data)
        expected = hashlib.sha384(data).hexdigest()
        assert rh_hasher.hexdigest() == expected


class TestDigestTools:
    """Tests for the digest_tools helper function."""

    def test_digest_from_hashlib(self):
        """Test the new digest_from_hashlib helper."""
        from digest.digest_tools import digest_from_hashlib

        h = resumablehash.sha512()
        h.update(b"test data")

        result = digest_from_hashlib("sha512", h)
        assert result.startswith("sha512:")
        assert result == f"sha512:{h.hexdigest()}"

    def test_digest_from_hashlib_sha384(self):
        """Test digest_from_hashlib with sha384."""
        from digest.digest_tools import digest_from_hashlib

        h = resumablehash.sha384()
        h.update(b"test data")

        result = digest_from_hashlib("sha384", h)
        assert result == f"sha384:{h.hexdigest()}"

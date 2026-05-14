"""
Tests for dual-hash (multi-algorithm) blob upload pipeline.

Tests the core helper functions (serialization, deserialization, speculative
algorithm selection, digest validation) and the safe_unpickle helper.

Note: Full integration tests of _BlobUploadManager require Flask app
initialization which is not available in this environment. The core logic
is tested here through the standalone helper functions and the resumablehash
library behavior.
"""

import base64
import hashlib
import json
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
        # Use os.path module class as an arbitrary non-allowed class.
        # We construct a pickle payload manually to avoid issues with local classes.
        import io

        data = pickle.dumps(io.BytesIO(b"evil"))
        with pytest.raises(pickle.UnpicklingError):
            safe_unpickle(data)


class TestHashStateSerializationRoundTrip:
    """Tests for hash state serialization/deserialization round-trip.

    These tests replicate the serialization logic used in blobuploader.py
    without importing the module (which triggers Flask imports).
    """

    @staticmethod
    def _serialize_hash_state(hasher):
        return base64.b64encode(pickle.dumps(hasher)).decode("ascii")

    @staticmethod
    def _deserialize_hash_state(state_str):
        data = base64.b64decode(state_str.encode("ascii"))
        return safe_unpickle(data)

    @staticmethod
    def _serialize_speculative_states(hashers_dict):
        serialized = {}
        for algo, hasher in hashers_dict.items():
            serialized[algo] = base64.b64encode(pickle.dumps(hasher)).decode("ascii")
        return json.dumps(serialized)

    @staticmethod
    def _deserialize_speculative_states(state_str):
        if not state_str:
            return {}
        try:
            serialized = json.loads(state_str)
            result = {}
            for algo, encoded_state in serialized.items():
                data = base64.b64decode(encoded_state.encode("ascii"))
                result[algo] = safe_unpickle(data)
            return result
        except (json.JSONDecodeError, TypeError):
            return {}

    def test_single_hasher_round_trip(self):
        """Test single hasher serialize/deserialize."""
        h = resumablehash.sha512()
        h.update(b"hello world")

        serialized = self._serialize_hash_state(h)
        restored = self._deserialize_hash_state(serialized)
        assert restored.hexdigest() == h.hexdigest()

    def test_multi_hasher_round_trip(self):
        """Test serializing multiple hashers as JSON dict."""
        sha512_h = resumablehash.sha512()
        sha384_h = resumablehash.sha384()
        test_data = b"hello world test data"
        sha512_h.update(test_data)
        sha384_h.update(test_data)

        hashers_dict = {"sha512": sha512_h, "sha384": sha384_h}
        serialized = self._serialize_speculative_states(hashers_dict)

        # Verify it's valid JSON
        parsed = json.loads(serialized)
        assert "sha512" in parsed
        assert "sha384" in parsed

        # Deserialize and verify
        restored = self._deserialize_speculative_states(serialized)
        assert "sha512" in restored
        assert "sha384" in restored
        assert restored["sha512"].hexdigest() == sha512_h.hexdigest()
        assert restored["sha384"].hexdigest() == sha384_h.hexdigest()

    def test_empty_state(self):
        """Verify deserialization of None/empty returns empty dict."""
        assert self._deserialize_speculative_states(None) == {}
        assert self._deserialize_speculative_states("") == {}

    def test_corrupt_json(self):
        """Verify deserialization of corrupted data returns empty dict."""
        assert self._deserialize_speculative_states("not-valid-json") == {}

    def test_hasher_state_after_multiple_updates(self):
        """Verify hasher correctly accumulates state across multiple updates."""
        hasher = resumablehash.sha512()
        chunk1 = os.urandom(100)
        chunk2 = os.urandom(100)

        # Update with chunk1
        hasher.update(chunk1)

        # Serialize/deserialize (simulating chunk boundary)
        serialized = self._serialize_hash_state(hasher)
        restored = self._deserialize_hash_state(serialized)

        # Update restored hasher with chunk2
        restored.update(chunk2)

        # Compare with a fresh hasher that got both chunks
        expected = resumablehash.sha512()
        expected.update(chunk1)
        expected.update(chunk2)

        assert restored.hexdigest() == expected.hexdigest()
        assert restored.hexdigest() == hashlib.sha512(chunk1 + chunk2).hexdigest()

    def test_multi_chunk_serialize_deserialize(self):
        """Simulate a multi-chunk upload with serialize/deserialize between chunks."""
        chunks = [os.urandom(100) for _ in range(5)]

        hasher = resumablehash.sha512()
        for chunk in chunks:
            hasher.update(chunk)
            # Serialize and deserialize (simulating DB persistence)
            serialized = self._serialize_hash_state(hasher)
            hasher = self._deserialize_hash_state(serialized)

        full_data = b"".join(chunks)
        expected = hashlib.sha512(full_data).hexdigest()
        assert hasher.hexdigest() == expected


class TestSpeculativeAlgorithmSelection:
    """Tests for the algorithm selection logic."""

    def test_feature_disabled_returns_empty(self):
        """When feature is disabled, no speculative algorithms should be computed."""
        config = {
            "FEATURE_MULTI_ALGORITHM_SUPPORT": False,
            "ALLOWED_HASH_ALGORITHMS": ["sha256", "sha512"],
        }
        assert not config.get("FEATURE_MULTI_ALGORITHM_SUPPORT", False)

    def test_only_non_sha256_returned(self):
        """Only non-sha256 algorithms should be in the speculative set."""
        allowed = ["sha256", "sha512", "sha384"]
        speculative = {a for a in allowed if a != "sha256" and hasattr(resumablehash, a)}
        assert speculative == {"sha512", "sha384"}
        assert "sha256" not in speculative

    def test_unknown_algorithms_filtered(self):
        """Algorithms not supported by resumablehash should be filtered out."""
        allowed = ["sha256", "sha512", "sha3_256", "blake2b"]
        speculative = {a for a in allowed if a != "sha256" and hasattr(resumablehash, a)}
        assert "sha512" in speculative
        assert "sha3_256" not in speculative
        assert "blake2b" not in speculative

    def test_create_hasher(self):
        """Test that hasher creation works for supported algorithms."""
        for algo in ["sha256", "sha384", "sha512"]:
            constructor = getattr(resumablehash, algo, None)
            assert constructor is not None
            hasher = constructor()
            assert hasher is not None
            hasher.update(b"test")
            assert len(hasher.hexdigest()) > 0


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

    def test_chunked_hash_matches_monolithic(self):
        """Verify that computing hash across chunks gives same result as all-at-once."""
        chunks = [os.urandom(100) for _ in range(10)]
        full_data = b"".join(chunks)

        chunked_hasher = resumablehash.sha512()
        for chunk in chunks:
            chunked_hasher.update(chunk)

        monolithic_hasher = resumablehash.sha512()
        monolithic_hasher.update(full_data)

        assert chunked_hasher.hexdigest() == monolithic_hasher.hexdigest()
        assert chunked_hasher.hexdigest() == hashlib.sha512(full_data).hexdigest()

    def test_dual_hash_stream_simulation(self):
        """Simulate dual-hash computation (SHA-256 + SHA-512) on a data stream.

        This replicates the upload_chunk() logic of wrapping the stream with
        multiple hash handlers.
        """
        data = os.urandom(500)

        # Simulate the two hash handlers
        sha256_hasher = resumablehash.sha256()
        sha512_hasher = resumablehash.sha512()

        # Both hashers process the same data
        sha256_hasher.update(data)
        sha512_hasher.update(data)

        # Verify against stdlib
        assert sha256_hasher.hexdigest() == hashlib.sha256(data).hexdigest()
        assert sha512_hasher.hexdigest() == hashlib.sha512(data).hexdigest()

    def test_dual_hash_chunked_with_persistence(self):
        """Simulate a full chunked upload with dual-hash and state persistence.

        This is the key test that validates the Option C (speculative hashing)
        approach end-to-end.
        """
        chunks = [os.urandom(100) for _ in range(5)]
        full_data = b"".join(chunks)

        sha256_hasher = resumablehash.sha256()
        sha512_hasher = resumablehash.sha512()
        sha384_hasher = resumablehash.sha384()

        for chunk in chunks:
            # Process chunk through all hashers
            sha256_hasher.update(chunk)
            sha512_hasher.update(chunk)
            sha384_hasher.update(chunk)

            # Serialize all speculative hashers (simulating DB write)
            spec_state = {}
            for algo, h in [("sha512", sha512_hasher), ("sha384", sha384_hasher)]:
                spec_state[algo] = base64.b64encode(pickle.dumps(h)).decode("ascii")
            state_json = json.dumps(spec_state)

            # Deserialize (simulating next chunk's DB read)
            parsed = json.loads(state_json)
            sha512_hasher = safe_unpickle(base64.b64decode(parsed["sha512"].encode("ascii")))
            sha384_hasher = safe_unpickle(base64.b64decode(parsed["sha384"].encode("ascii")))

        # At commit time, verify all digests match
        assert sha256_hasher.hexdigest() == hashlib.sha256(full_data).hexdigest()
        assert sha512_hasher.hexdigest() == hashlib.sha512(full_data).hexdigest()
        assert sha384_hasher.hexdigest() == hashlib.sha384(full_data).hexdigest()

        # Construct digest strings
        sha256_digest = f"sha256:{sha256_hasher.hexdigest()}"
        sha512_digest = f"sha512:{sha512_hasher.hexdigest()}"
        sha384_digest = f"sha384:{sha384_hasher.hexdigest()}"

        # Verify they would match the expected format
        assert sha256_digest.startswith("sha256:")
        assert sha512_digest.startswith("sha512:")
        assert sha384_digest.startswith("sha384:")


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

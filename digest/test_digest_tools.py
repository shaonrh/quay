import hashlib

import pytest

from digest.digest_tools import compute_digest


def test_compute_digest_sha256():
    """Verify compute_digest with SHA-256 produces the correct digest string."""
    data = b"hello"
    expected_hash = hashlib.sha256(data).hexdigest()
    result = compute_digest("sha256", data)
    assert result == f"sha256:{expected_hash}"


def test_compute_digest_sha512():
    """Verify compute_digest with SHA-512 produces the correct digest string."""
    data = b"hello world"
    expected_hash = hashlib.sha512(data).hexdigest()
    result = compute_digest("sha512", data)
    assert result == f"sha512:{expected_hash}"


def test_compute_digest_sha3_256():
    """Verify the OCI-to-hashlib name mapping for sha3-256 -> sha3_256."""
    data = b"test data"
    expected_hash = hashlib.new("sha3_256", data).hexdigest()
    result = compute_digest("sha3-256", data)
    assert result == f"sha3-256:{expected_hash}"


def test_compute_digest_unsupported():
    """Verify ValueError is raised for an unsupported hash algorithm."""
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        compute_digest("not-a-real-algorithm", b"data")

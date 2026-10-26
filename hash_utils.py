"""
hash_utils.py
-------------
Utility functions for computing and comparing SHA-256 file hashes.

SHA-256 (Secure Hash Algorithm 256-bit) produces a fixed-length 64-character
hexadecimal string from any input.  Even a single changed byte produces a
completely different hash, making it ideal for detecting file tampering.
"""

import hashlib
from typing import BinaryIO


# Maximum chunk size when reading large files (1 MiB)
CHUNK_SIZE = 1_048_576


def compute_hash_from_bytes(data: bytes) -> str:
    """
    Return the SHA-256 hex digest of a raw bytes object.

    Used when the entire file content is already in memory (e.g. during tests
    or when the uploaded file object is small).

    Args:
        data: Raw bytes to hash.

    Returns:
        64-character lowercase hexadecimal string.
    """
    return hashlib.sha256(data).hexdigest()


def compute_hash_from_stream(file_stream: BinaryIO) -> str:
    """
    Return the SHA-256 hex digest by reading *file_stream* in chunks.

    Reading in chunks avoids loading the entire file into memory, which is
    important for large files.  The stream is read from its current position;
    callers should seek(0) beforehand if needed.

    Args:
        file_stream: A file-like object opened in binary mode.

    Returns:
        64-character lowercase hexadecimal string.
    """
    sha256 = hashlib.sha256()
    while True:
        chunk = file_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        sha256.update(chunk)
    return sha256.hexdigest()


def hashes_match(hash_a: str, hash_b: str) -> bool:
    """
    Return True if two SHA-256 hex digests are equal (case-insensitive).

    Args:
        hash_a: First hash string.
        hash_b: Second hash string.

    Returns:
        Boolean indicating whether the hashes match.
    """
    return hash_a.strip().lower() == hash_b.strip().lower()

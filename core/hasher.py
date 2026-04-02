"""SHA-256 file hashing with chunked reads."""

import hashlib
import logging

from config.settings import CHUNK_SIZE
from core.exceptions import HashError

logger = logging.getLogger(__name__)


def hash_file(path: str) -> str:
    """Compute the SHA-256 hash of a file using chunked reads.

    Args:
        path: Absolute path to the file.

    Returns:
        Hexadecimal SHA-256 digest string.

    Raises:
        HashError: If the file cannot be read (permission denied or not found).
    """
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
    except (PermissionError, FileNotFoundError) as exc:
        raise HashError(path, exc) from exc
    return hasher.hexdigest()

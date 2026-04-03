"""AES-256-GCM encryption and SHA-256 signature for the baseline file."""

import hashlib
import json
import logging
import os
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from core.exceptions import SignatureError

logger = logging.getLogger(__name__)

_PBKDF2_ITERATIONS = 100_000
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_baseline(path: str, key: str, enc_path: str) -> str:
    """Encrypt a baseline JSON file with AES-256-GCM.

    Output format: [salt 16B][nonce 12B][ciphertext+tag].

    Args:
        path: Path to the plaintext baseline JSON file.
        key: Encryption password (from ROOTGUARD_ENCRYPT_KEY env var).
        enc_path: Destination path for the encrypted file.

    Returns:
        Path to the encrypted file.
    """
    with open(path, "rb") as f:
        data = f.read()

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    derived = _derive_key(key, salt)
    aesgcm = AESGCM(derived)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # includes 16B GCM tag

    os.makedirs(os.path.dirname(enc_path) or ".", exist_ok=True)
    with open(enc_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    try:
        os.chmod(enc_path, stat.S_IRUSR)
    except OSError as exc:
        logger.warning("Could not set .enc read-only: %s", exc)

    logger.info("Baseline encrypted to %s", enc_path)
    return enc_path


def decrypt_baseline(enc_path: str, key: str) -> dict:
    """Decrypt an AES-256-GCM encrypted baseline file.

    Args:
        enc_path: Path to the encrypted baseline file.
        key: Decryption password.

    Returns:
        The ``files`` dict from the decrypted baseline JSON.

    Raises:
        cryptography.exceptions.InvalidTag: If key is wrong or file is corrupted.
    """
    with open(enc_path, "rb") as f:
        raw = f.read()

    salt = raw[:_SALT_SIZE]
    nonce = raw[_SALT_SIZE:_SALT_SIZE + _NONCE_SIZE]
    ciphertext = raw[_SALT_SIZE + _NONCE_SIZE:]

    derived = _derive_key(key, salt)
    aesgcm = AESGCM(derived)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    payload = json.loads(plaintext)
    return payload["files"]


def sign_baseline(path: str, sig_path: str) -> str:
    """Compute and store the SHA-256 hash of the baseline file.

    Args:
        path: Path to the baseline JSON file.
        sig_path: Destination path for the signature file.

    Returns:
        The hexadecimal SHA-256 digest.
    """
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    os.makedirs(os.path.dirname(sig_path) or ".", exist_ok=True)
    with open(sig_path, "w") as f:
        f.write(digest)

    try:
        os.chmod(sig_path, stat.S_IRUSR)
    except OSError as exc:
        logger.warning("Could not set .sig read-only: %s", exc)

    logger.info("Baseline signed: %s", sig_path)
    return digest


def verify_signature(path: str, sig_path: str) -> None:
    """Verify the SHA-256 signature of a baseline file.

    Args:
        path: Path to the file to verify.
        sig_path: Path to the signature file produced by ``sign_baseline()``.

    Raises:
        SignatureError: If the current hash does not match the stored signature.
    """
    with open(path, "rb") as f:
        current = hashlib.sha256(f.read()).hexdigest()

    with open(sig_path, "r") as f:
        expected = f.read().strip()

    if current != expected:
        raise SignatureError(path)

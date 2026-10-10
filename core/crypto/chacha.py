import os
from blake3 import blake3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from core.crypto.blake3 import get_blake3_hash


class AuthenticationError(ValueError):
    """Raised when the Poly1305 tag check fails (wrong key or tampered blob/AD)."""
    pass

def get_nonce(data: bytes, key: bytes | None = None, additional_data: bytes | None = None) -> bytes:
    """
    Deterministic synthetic nonce (SIV-style): keyed BLAKE3 over AD+message.

    No counter/state to track: the same (key, AD, message) always yields the
    same nonce, different messages yield different nonces (up to 96-bit hash
    collisions). The key MUST be bound in (unlike hashing the message alone),
    otherwise equal plaintexts under different keys share nonces and an
    attacker can predict nonces.

    Tradeoff vs random nonces: repeats of the exact same (key, AD, message)
    produce identical blobs (equality leak), but there is no catastrophic
    keystream reuse across *different* messages and no RNG/state needed.

    Args:
        data (bytes): Plaintext message.
        key (bytes | None): 32-byte ChaCha key. Mixed into the hash when given.
        additional_data (bytes | None): AD bound into the nonce when given.
    Returns:
        bytes: A deterministic 12-byte nonce.
    """
    ad = additional_data if additional_data is not None else b""
    if key is not None and len(key) == 32:
        return blake3(ad + data, key=key).digest(12)
    h = blake3()
    if key:
        h.update(key)
    h.update(ad)
    h.update(data)
    return h.digest(12)

def encrypt(data: bytes, key: bytes, additional_data: bytes | None = None) -> bytes:
    """
    Encrypts the given data using ChaCha20Poly1305 with the provided key.

    Packs unencrypted-but-authenticated additional data into the output so
    the caller only has to transport a single blob.

    Wire format: ad_len(4B big-endian) || ad || nonce(12B) || ct+tag

    Args:
        data (bytes): The plaintext data to encrypt.
        key (bytes): The encryption key (must be 32 bytes).
        additional_data (bytes | None): Additional authenticated data
            (sent in the clear, but tamper-protected by the Poly1305 tag).
    Returns:
        bytes: The packed blob containing AD, nonce, and ciphertext+tag.
    """
    ad = additional_data if additional_data is not None else b""
    nonce = get_nonce(data, key=key, additional_data=ad if ad else None)
    chacha = ChaCha20Poly1305(key)
    encrypted_data = chacha.encrypt(nonce, data, ad if ad else None)
    return len(ad).to_bytes(4, "big") + ad + nonce + encrypted_data

def decrypt(encrypted_data: bytes, key: bytes) -> tuple[bytes, bytes | None]:
    """
    Decrypts a blob produced by encrypt(), extracting the packed AD.

    Args:
        encrypted_data (bytes): The packed blob: ad_len || ad || nonce || ct+tag.
        key (bytes): The decryption key (must be 32 bytes).
    Returns:
        tuple[bytes, bytes | None]: (plaintext, additional_data). additional_data
            is None when the sender packed no AD.
    Raises:
        ValueError: If the blob is malformed.
        AuthenticationError: If the Poly1305 tag check fails
            (wrong key or tampered AD/ciphertext/tag).
    """
    if len(encrypted_data) < 4 + 12 + 16:
        raise ValueError("Decryption failed: blob too short.")
    ad_len = int.from_bytes(encrypted_data[:4], "big")
    if len(encrypted_data) < 4 + ad_len + 12 + 16:
        raise ValueError("Decryption failed: blob truncated.")
    ad = encrypted_data[4:4 + ad_len]
    nonce = encrypted_data[4 + ad_len:4 + ad_len + 12]
    ciphertext = encrypted_data[4 + ad_len + 12:]
    chacha = ChaCha20Poly1305(key)
    try:
        decrypted_data = chacha.decrypt(nonce, ciphertext, ad if ad else None)
        return decrypted_data, (ad if ad else None)
    except InvalidTag:
        raise AuthenticationError("Decryption failed: Invalid authentication tag.") from None

def get_ad(encrypted_data: bytes) -> bytes | None:
    """
    Extracts the packed additional data without the key (no verification).

    Note: returned AD is UNTRUSTED until decrypt() succeeds with the key.
    Use for routing/display only; never enforce security on it alone.

    Args:
        encrypted_data (bytes): The packed blob: ad_len || ad || nonce || ct+tag.
    Returns:
        bytes | None: The cleartext AD, or None when no AD was packed.
    Raises:
        ValueError: If the blob is malformed.
    """
    if len(encrypted_data) < 4:
        raise ValueError("AD parse failed: blob too short.")
    ad_len = int.from_bytes(encrypted_data[:4], "big")
    if len(encrypted_data) < 4 + ad_len + 12:
        raise ValueError("AD parse failed: blob truncated.")
    ad = encrypted_data[4:4 + ad_len]
    return ad if ad else None
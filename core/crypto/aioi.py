"""TPS (Two Packet Strength): KEM with resolvable ambiguity.

The sender does not know its role (A or B) relative to the peer, so it
encapsulates under both role hypotheses; only the role-complementary
packet is valid and the peer resolves which one won. With ``tps=False``
this collapses to single-shot encaps/decaps with no selection round.
Costs ~2x442KB per message (swoosh pubkeys ride as AD).
"""
from core.crypto.x_keys import KeyXchange
from core.keys.generate import generate_swoosh
from core.crypto.blake3 import get_blake3_hash
from core.crypto import chacha

_KDF_DOMAIN = b"pqep-aioi-v1"
_SEED_DOMAIN = b"pqep-aioi-seed-v1"


def _derive_key(shared_secret: bytes) -> bytes:
    """Derive the ChaCha transport key from a raw swoosh secret.

    Args:
        shared_secret (bytes): 32-byte raw swoosh shared secret.

    Returns:
        bytes: 32-byte domain-separated key
        (``BLAKE3(secret + "pqep-aioi-v1")``).

    Note:
        Never use the raw shared secret as a transport key directly.
    """
    return get_blake3_hash(shared_secret + _KDF_DOMAIN, 32)


def _role_seed(master_seed: bytes, party_a: bool) -> bytes:
    """Derive a role-bound 32-byte subseed from the 32-byte master seed.

    Role A and role B keypairs come from independent subseeds, so the two
    TPS identities are cryptographically separated even though they share
    one master seed. Deterministic: same (master, role) -> same subseed,
    so the receiver re-derives the identical local keypair.

    Args:
        master_seed (bytes): 32-byte master seed.
        party_a (bool): Role to derive for (``0x01`` for A, ``0x00`` for B).

    Returns:
        bytes: 32-byte role-bound subseed.
    """
    role = b"\x01" if party_a else b"\x00"
    return get_blake3_hash(_SEED_DOMAIN + role + bytes(master_seed), 32)


def _check_seed(seed) -> None:
    """Validate a master seed.

    Args:
        seed: Candidate 32-byte master seed.

    Raises:
        ValueError: Unless ``seed`` is 32-byte ``bytes``.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("sk_pqep must be a 32-byte seed.")


def _enc_one(seed, peer_pub, message, party_a):
    """Single-role encrypt: one TPS hypothesis.

    Args:
        seed: 32-byte master seed (role subseed derived internally).
        peer_pub (bytes): Peer's swoosh public-key bytes.
        message (bytes): Plaintext message.
        party_a (bool): Local role hypothesis for this packet.

    Returns:
        tuple[bytes, bytes]: ``(blob, sender_pubkey_bytes)``. Blob wire
        format is ``ad_len || ad || nonce || ct+tag`` with the sender's
        swoosh pubkey as packed AD.

    Raises:
        KeyExchangeError: If shared-secret derivation fails.
    """
    sk_s, pk_s = generate_swoosh(is_party_a=party_a, seed=_role_seed(seed, party_a))
    shared_secret = KeyXchange(sk_s, pk_s, peer_pub, party_a).exchange()
    blob = chacha.encrypt(data=message, key=_derive_key(shared_secret), additional_data=pk_s)
    return blob, pk_s


def encrypt(sk_pqep, pk_o, message, party_a=True, tps=True):
    """TPS encrypt entry point.

    Args:
        sk_pqep (bytes): 32-byte master seed (never fed to keygen directly;
            role subseeds are derived via :func:`_role_seed`).
        pk_o (bytes): Peer's swoosh public-key bytes.
        message (bytes): Plaintext message.
        party_a (bool): Assumed local role for the first packet.
        tps (bool): If True, emit both role hypotheses; if False, emit a
            single packet (single-shot encaps, no selection round).

    Returns:
        tuple: ``(blob1, blob2, pk1, pk2)`` with ``tps=True``, else
        ``(blob, pk, None, None)``.

    Note:
        Only the role-complementary packet is valid to the peer; the other
        is undecryptable by design. Its hashes are still witnessed in the
        confirmation step for downgrade detection.

    Raises:
        ValueError: On bad input types or sizes.
        KeyExchangeError: If shared-secret derivation fails.
    """
    _check_seed(sk_pqep)
    if not isinstance(pk_o, (bytes, bytearray)) or len(pk_o) == 0:
        raise ValueError("pk_o must be the peer's swoosh public-key bytes.")
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("message must be bytes.")
    encrypted_message, pk_s = _enc_one(sk_pqep, bytes(pk_o), bytes(message), party_a)
    if tps:
        encrypted_message2, pk_s2 = _enc_one(sk_pqep, bytes(pk_o), bytes(message), not party_a)
        return encrypted_message, encrypted_message2, pk_s, pk_s2
    return encrypted_message, pk_s, None, None


def encapsulate(sk_pqep, pk_o, payload, party_a=True, tps=True):
    """Encapsulate like :func:`encrypt` but retain per-candidate secrets.

    Exists so the sender can *remember* what it used: the returned
    candidates hold each hypothesis' local pubkey, raw shared secret,
    derived transport key, blob, and blob hash. No re-derivation needed
    when the peer's reply arrives.

    Args:
        sk_pqep (bytes): 32-byte master seed.
        pk_o (bytes): Peer's swoosh public-key bytes.
        payload (bytes): Plaintext payload (e.g. our X25519 ephemeral pub).
        party_a (bool): Local role hypothesis for the first packet.
        tps (bool): If True, encapsulate under both roles.

    Returns:
        tuple[tuple, tuple]: ``(blobs, candidates)``. ``blobs`` mirrors
        :func:`encrypt` (``(b1, b2)`` or ``(b1,)``); each candidate is a
        dict ``{"role", "local_pubkey", "shared_secret", "key",
        "blob", "blob_hash"}`` where ``key`` is ``_derive_key`` output and
        ``blob_hash`` is ``BLAKE3(blob)`` (32B, for transcripts).

    Raises:
        ValueError: On bad input types or sizes.
        KeyExchangeError: If shared-secret derivation fails.
    """
    from core.crypto.blake3 import get_blake3_hash as _h
    _check_seed(sk_pqep)
    if not isinstance(pk_o, (bytes, bytearray)) or len(pk_o) == 0:
        raise ValueError("pk_o must be the peer's swoosh public-key bytes.")
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes.")
    roles = (party_a, not party_a) if tps else (party_a,)
    blobs, candidates = [], []
    for role in roles:
        sub = _role_seed(sk_pqep, role)
        sk_s, pk_s = generate_swoosh(is_party_a=role, seed=sub)
        secret = KeyXchange(sk_s, pk_s, bytes(pk_o), role).exchange()
        key = _derive_key(secret)
        blob = chacha.encrypt(data=bytes(payload), key=key, additional_data=pk_s)
        blobs.append(blob)
        candidates.append({
            "role": role,
            "local_pubkey": pk_s,
            "shared_secret": secret,
            "key": key,
            "blob": blob,
            "blob_hash": _h(blob, 32),
        })
    return tuple(blobs), tuple(candidates)


def _dec_one(seed, encrypted_message, party_a):
    """Single-role decrypt attempt.

    Args:
        seed: 32-byte master seed (role subseed derived internally).
        encrypted_message (bytes): One packed blob.
        party_a (bool): Local role to try for this attempt.

    Returns:
        tuple[bytes, bytes, bytes, bytes]: ``(plaintext, sender_pubkey,
        local_pubkey, shared_secret)`` with the raw swoosh secret
        (derive transport keys via :func:`_derive_key`).

    Raises:
        ValueError: If the blob carries no sender pubkey.
        AuthenticationError: If the Poly1305 tag check fails.
        KeyExchangeError: If shared-secret derivation fails.
    """
    pk_o = chacha.get_ad(encrypted_message)
    if pk_o is None:
        raise ValueError("Decryption failed: blob carries no sender pubkey.")
    sk_s, pk_s = generate_swoosh(is_party_a=party_a, seed=_role_seed(seed, party_a))
    shared_secret = KeyXchange(sk_s, pk_s, pk_o, party_a).exchange()
    plaintext, _ = chacha.decrypt(encrypted_data=encrypted_message, key=_derive_key(shared_secret))
    return plaintext, pk_o, pk_s, shared_secret


def decrypt(sk_pqep, encrypted_message, party_a=True, tps=True):
    """TPS decrypt entry point; tries each blob x each role, first win returns.

    Args:
        sk_pqep (bytes): 32-byte master seed.
        encrypted_message: Single blob or list of blobs to try in order.
        party_a (bool): Assumed local role; tried first when ``tps=True``.
        tps (bool): If True, also try the flipped role per blob.

    Returns:
        bytes: Plaintext of the winning combination.

    Note:
        Pass *both* blobs as a list -- a lone role-mismatched blob can
        never decrypt, by design.

    Raises:
        ValueError: On malformed input (bad seed, non-bytes blob, no blobs).
        AuthenticationError: If nothing authenticates (wrong seed, tampered
            data, or role-mismatched packet).
    """
    return select(sk_pqep, encrypted_message, party_a, tps)[0]


def select(sk_pqep, encrypted_message, party_a=True, tps=True):
    """TPS selection: decrypt while reporting which combination won.

    Same 2x2 trial loop as :func:`decrypt`, but instead of discarding the
    winner it returns the winning public keys and shared secret so the
    caller (e.g. the confirmation handshake) can bind them into a
    transcript and derive session keys.

    Args:
        sk_pqep (bytes): 32-byte master seed.
        encrypted_message: Single blob or list of blobs to try in order.
        party_a (bool): Assumed local role; tried first when ``tps=True``.
        tps (bool): If True, also try the flipped role per blob.

    Returns:
        tuple[bytes, dict]: ``(plaintext, info)`` where ``info`` holds::

            {"blob_index": int, "role": bool,
             "sender_pubkey": bytes, "local_pubkey": bytes,
             "shared_secret": bytes}  # raw swoosh secret, KDF via _derive_key

    Raises:
        ValueError: On malformed input (bad seed, non-bytes blob, no blobs).
        AuthenticationError: If nothing authenticates (wrong seed, tampered
            data, or role-mismatched packet).
    """
    _check_seed(sk_pqep)
    if isinstance(encrypted_message, (tuple, list)):
        blobs = list(encrypted_message)
    else:
        blobs = [encrypted_message]
    if not blobs:
        raise ValueError("Decryption failed: no blobs provided.")
    roles = (party_a, not party_a) if tps else (party_a,)
    last_err = None
    for index, blob in enumerate(blobs):
        if not isinstance(blob, (bytes, bytearray)):
            raise ValueError("Decryption failed: blob must be bytes.")
        for role in roles:
            try:
                plaintext, sender_pk, local_pk, secret = _dec_one(sk_pqep, bytes(blob), role)
                return plaintext, {
                    "blob_index": index,
                    "role": role,
                    "sender_pubkey": sender_pk,
                    "local_pubkey": local_pk,
                    "shared_secret": secret,
                }
            except chacha.AuthenticationError as e:
                last_err = e
                continue
    raise chacha.AuthenticationError("Decryption failed: Invalid authentication tag.") from last_err


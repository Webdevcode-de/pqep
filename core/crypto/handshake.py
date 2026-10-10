"""Confirmed handshake: TPS propose -> select -> X25519 reply -> session.

Flow:
  A: blobs, handle = propose(...)   # remembers candidates + ephemeral X25519
  B: reply_blob, sig = reply(...)   # stateless; selects winner, sends X25519 half
  A: session = resolve(...)         # trial-decrypts with remembered candidates

B never stores per-handshake state. A stores the opaque
:class:`PendingHandshake` until ``resolve``/``abort`` (single-use, TTL'd).
"""
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from core.crypto import aioi, chacha
from core.crypto.blake3 import get_blake3_hash
from core.keys.generate import generate_x25519

_SESS_DOMAIN = b"pqep-session-v1"
_HANDLE_TTL = 300.0
_HELLO_VERSION = b"\x48"
_REPLY_VERSION = b"\x52"


class PendingHandshake:
    """Opaque sender-side memory for one handshake attempt (single-use)."""

    __slots__ = (
        "candidates",
        "blobs",
        "esk",
        "epk_raw",
        "peer_pk",
        "transcript",
        "created_at",
        "used",
        "ttl",
    )

    def __init__(self, candidates, blobs, esk, epk_raw, peer_pk,
                 transcript, ttl=_HANDLE_TTL):
        self.candidates = candidates
        self.blobs = blobs
        self.esk = esk
        self.epk_raw = epk_raw
        self.peer_pk = peer_pk
        self.transcript = transcript
        self.created_at = time.monotonic()
        self.used = False
        self.ttl = ttl

    @property
    def expired(self):
        """Whether this handle is past its TTL."""
        return (time.monotonic() - self.created_at) > self.ttl


def _transcript(candidates, peer_pk):
    """Bind the blob-hash pair into 32 bytes.

    Built from blob hashes only (pubkeys ride inside the blobs as AD, so
    they are covered transitively). Both sides compute the identical value:
    A from its candidates, B from the received blobs via
    :func:`_transcript_select`.
    """
    _ = peer_pk  # part of blobs' AD; kept in signature for callers.
    return get_blake3_hash(b"".join(c["blob_hash"] for c in candidates), 32)


def abort(handle):
    """Discard a pending handshake and zeroize what we can.

    Args:
        handle (PendingHandshake): Handle to destroy (idempotent).
    """
    for attr in ("candidates", "blobs", "esk", "epk_raw", "peer_pk",
                 "transcript"):
        try:
            setattr(handle, attr, None)
        except AttributeError:
            pass
    try:
        handle.used = True
    except AttributeError:
        pass


def propose(sk_pqep, pk_o, party_a=True, tps=True, ed_pub_raw=None,
            ttl=_HANDLE_TTL):
    """Start a handshake (party A side): encapsulate our X25519 half.

    Args:
        sk_pqep (bytes): 32-byte swoosh master seed.
        pk_o (bytes): Peer's swoosh public-key bytes.
        party_a (bool): Assumed local role for the first packet.
        tps (bool): Encapsulate under both roles (resolvable ambiguity).
        ed_pub_raw (bytes | None): Optional 32-byte Ed25519 identity pub
            to advertise inside the encrypted hello (zeros if omitted).
        ttl (float): Handle lifetime in seconds.

    Returns:
        tuple[tuple, PendingHandshake]: ``(blobs, handle)``. Send ``blobs``
        to B, keep ``handle`` for :func:`resolve`.

    Raises:
        ValueError: On bad inputs.
        KeyExchangeError: If encapsulation fails.
    """
    if ed_pub_raw is None:
        ed_pub_raw = b"\x00" * 32
    if not isinstance(ed_pub_raw, (bytes, bytearray)) or len(ed_pub_raw) != 32:
        raise ValueError("ed_pub_raw must be 32 bytes or None.")
    esk, _ = generate_x25519()
    epk_raw = esk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = _HELLO_VERSION + epk_raw + bytes(ed_pub_raw)
    blobs, candidates = aioi.encapsulate(sk_pqep, pk_o, payload,
                                         party_a, tps)
    transcript = _transcript(candidates, bytes(pk_o))
    handle = PendingHandshake(candidates, blobs, esk, epk_raw,
                              bytes(pk_o), transcript, ttl)
    return blobs, handle


def _parse_hello(payload):
    if len(payload) != 1 + 32 + 32 or payload[:1] != _HELLO_VERSION:
        raise ValueError("Reply failed: malformed hello payload.")
    return payload[1:33], payload[33:65]


def reply(sk_pqep, blobs, party_a=True, tps=True, ed_sign_key=None):
    """Answer a handshake (party B side). Stateless.

    Selects the winning TPS packet, then sends back our X25519 ephemeral
    half encrypted under the winner secret, signed with Ed25519.

    Args:
        sk_pqep (bytes): 32-byte swoosh master seed.
        blobs: One blob or list of blobs received from A.
        party_a (bool): Assumed local role; flipped role also tried.
        tps (bool): Try both local roles per blob.
        ed_sign_key: Ed25519PrivateKey for the reply signature (required).

    Returns:
        tuple[bytes, bytes]: ``(reply_blob, signature)`` to send back to A.

    Raises:
        ValueError: If ``ed_sign_key`` is missing or input malformed.
        AuthenticationError: If no blob authenticates.
        KeyExchangeError: If derivation fails.
    """
    if ed_sign_key is None:
        raise ValueError("reply requires ed_sign_key (Both-auth mode).")
    plaintext, info = aioi.select(sk_pqep, blobs, party_a, tps)
    epk_a_raw, _ed_a = _parse_hello(plaintext)
    # Validate A's X25519 half parses as a real pubkey (fail fast).
    X25519PublicKey.from_public_bytes(epk_a_raw)
    esk_b, _ = generate_x25519()
    epk_b_raw = esk_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if isinstance(blobs, (bytes, bytearray)):
        blob_list = [bytes(blobs)]
    else:
        blob_list = [bytes(b) for b in blobs]
    h1 = get_blake3_hash(blob_list[0], 32)
    h2 = get_blake3_hash(blob_list[1], 32) if len(blob_list) > 1 else b"\x00" * 32
    role_byte = b"\x01" if info["role"] else b"\x00"
    reply_payload = _REPLY_VERSION + epk_b_raw + h1 + h2 + role_byte
    key = aioi._derive_key(info["shared_secret"])
    reply_blob = chacha.encrypt(data=reply_payload, key=key,
                                additional_data=info["local_pubkey"])
    signature = ed_sign_key.sign(reply_blob)
    # B keeps nothing, but needs its ephemeral + winner secret to talk next.
    # Return them alongside (caller-owned memory, not library state).
    ctx = {
        "esk_raw": esk_b.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                       NoEncryption()),
        "epk_a_raw": epk_a_raw,
        "winner_secret": info["shared_secret"],
        "transcript": _transcript_select(info, blob_list),
    }
    return reply_blob, signature, ctx


def _transcript_select(info, blob_list):
    """B-side mirror of :func:`_transcript`: hash of per-blob hashes."""
    _ = info  # winner detail not needed; blob hashes fully determine it.
    return get_blake3_hash(
        b"".join(get_blake3_hash(b, 32) for b in blob_list), 32)


def _parse_reply(payload, expect_hashes):
    if len(payload) != 1 + 32 + 32 + 32 + 1 or payload[:1] != _REPLY_VERSION:
        raise ValueError("Resolve failed: malformed reply payload.")
    epk = payload[1:33]
    h1, h2, role = payload[33:65], payload[65:97], payload[97:98]
    if h1 != expect_hashes[0] or h2 != expect_hashes[1]:
        raise chacha.AuthenticationError(
            "Resolve failed: reply references unknown blobs (downgrade?).")
    X25519PublicKey.from_public_bytes(epk)
    return epk, bool(role[0])


def resolve(handle, reply_blob, signature, ed_verify_key):
    """Complete the handshake (party A side) -> established Session.

    Trial-decrypts the reply with the *remembered* candidates (no KEM
    re-derivation), verifies transcript binding + Ed25519 signature, runs
    X25519 ECDH, and destroys the handle.

    Args:
        handle (PendingHandshake): From :func:`propose` (single-use).
        reply_blob (bytes): B's encrypted reply.
        signature (bytes): B's 64-byte Ed25519 signature over it.
        ed_verify_key: Pinned Ed25519PublicKey of B (required).

    Returns:
        Session: Established channel (A side).

    Raises:
        ValueError: On expired/consumed handle or malformed input.
        AuthenticationError: On bad signature, failed decrypt, or hash
            mismatch. Never falls back to the loser packet.
    """
    if not isinstance(handle, PendingHandshake) or handle.used:
        raise ValueError("Resolve failed: handle already consumed.")
    if handle.expired:
        abort(handle)
        raise ValueError("Resolve failed: handle expired.")
    if ed_verify_key is None:
        abort(handle)
        raise ValueError("resolve requires ed_verify_key (Both-auth mode).")
    try:
        ed_verify_key.verify(signature, bytes(reply_blob))
    except InvalidSignature:
        abort(handle)
        raise chacha.AuthenticationError(
            "Resolve failed: bad Ed25519 signature.") from None
    expect = (handle.candidates[0]["blob_hash"],
              handle.candidates[1]["blob_hash"]
              if len(handle.candidates) > 1 else b"\x00" * 32)
    last_err = None
    for cand in handle.candidates:
        try:
            payload, _ad = chacha.decrypt(bytes(reply_blob), cand["key"])
        except chacha.AuthenticationError as e:
            last_err = e
            continue
        try:
            epk_b_raw, role_b = _parse_reply(payload, expect)
        except (ValueError, chacha.AuthenticationError) as e:
            last_err = e
            continue
        if role_b == cand["role"]:
            # B's winning role must complement ours; equal roles mean
            # the reply was built for the other hypothesis (or forged).
            last_err = chacha.AuthenticationError(
                "Resolve failed: role mismatch in reply.")
            continue
        epk_b = X25519PublicKey.from_public_bytes(epk_b_raw)
        x_ss = handle.esk.exchange(epk_b)
        k_session = get_blake3_hash(
            x_ss + cand["shared_secret"] + handle.transcript + _SESS_DOMAIN, 32)
        session = Session(k_session, handle.transcript[:16], side="A")
        abort(handle)
        return session
    abort(handle)
    raise chacha.AuthenticationError(
        "Resolve failed: reply matches no remembered candidate.") from last_err


def session_for_b(ctx):
    """Build B's matching Session from the ctx returned by :func:`reply`.

    Args:
        ctx (dict): Opaque context from :func:`reply`.

    Returns:
        Session: Established channel (B side).
    """
    esk_b = X25519PrivateKey.from_private_bytes(ctx["esk_raw"])
    epk_a = X25519PublicKey.from_public_bytes(ctx["epk_a_raw"])
    x_ss = esk_b.exchange(epk_a)
    k_session = get_blake3_hash(
        x_ss + ctx["winner_secret"] + ctx["transcript"] + _SESS_DOMAIN, 32)
    try:
        sid = ctx["transcript"][:16]
    except Exception:
        sid = b"\x00" * 16
    return Session(k_session, sid, side="B")


class Session:
    """Established ChaCha channel with ordered, replay-proof delivery."""

    __slots__ = ("key", "session_id", "side", "send_seq", "recv_seq")

    def __init__(self, key, session_id, side):
        self.key = bytes(key)
        self.session_id = bytes(session_id)
        self.side = side
        self.send_seq = 0
        self.recv_seq = 0

    def _ad(self, seq):
        return self.session_id + int(seq).to_bytes(8, "big")

    def seal(self, plaintext):
        """Encrypt one message; AD binds session id + sequence.

        Args:
            plaintext (bytes): Message bytes.

        Returns:
            bytes: Packed blob to transmit.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise ValueError("plaintext must be bytes.")
        blob = chacha.encrypt(bytes(plaintext), self.key,
                              self._ad(self.send_seq))
        self.send_seq += 1
        return blob

    def open(self, blob):
        """Decrypt the next in-order message.

        Args:
            blob (bytes): Blob from :meth:`seal`.

        Returns:
            bytes: Plaintext.

        Raises:
            AuthenticationError: On tamper or out-of-order delivery.
        """
        plaintext, ad = chacha.decrypt(bytes(blob), self.key)
        if ad != self._ad(self.recv_seq):
            raise chacha.AuthenticationError(
                "Session open failed: unexpected sequence (replay/reorder?).")
        self.recv_seq += 1
        return plaintext

    def rekey(self):
        """Ratchet the session key forward; resets sequence counters."""
        self.key = get_blake3_hash(self.key + _SESS_DOMAIN + b"rekey", 32)
        self.send_seq = 0
        self.recv_seq = 0

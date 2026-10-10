"""Simple CLI to exercise the TPS + X25519 handshake and session channel.

Usage (from E:\\pqep with the venv python):
    python cli.py demo     # full A->B handshake + bidirectional traffic
    python cli.py tamper   # negative matrix (must all reject)
    python cli.py sizes    # blob / key sizes
"""
import argparse
import sys
import time

sys.path.insert(0, ".")

from core.crypto import aioi, chacha, handshake
from core.keys.generate import generate_ed25519, generate_swoosh
from seeds.seeds import tmp_master_seed


def make_peers():
    sA, sB = tmp_master_seed(), tmp_master_seed()
    _, pkB = generate_swoosh(False, aioi._role_seed(sB, False))
    ed_b_priv, ed_b_pub = generate_ed25519()
    return (sA, sB, pkB, ed_b_priv, ed_b_pub)


def cmd_demo(_args):
    sA, sB, pkB, ed_b_priv, ed_b_pub = make_peers()
    t0 = time.perf_counter()
    blobs, handle = handshake.propose(sA, pkB, party_a=True, tps=True)
    t1 = time.perf_counter()
    print(f"propose: {len(blobs)} blobs, "
          f"sizes={[len(b) for b in blobs]}, "
          f"transcript={handle.transcript.hex()[:16]}... "
          f"({(t1 - t0) * 1000:.0f} ms)")
    print(f"handle remembers: {len(handle.candidates)} candidates, "
          f"epk_A={handle.epk_raw.hex()[:16]}...")

    t0 = time.perf_counter()
    reply_blob, sig, ctx_b = handshake.reply(sB, list(blobs), party_a=False,
                                             tps=True, ed_sign_key=ed_b_priv)
    t1 = time.perf_counter()
    print(f"reply: blob={len(reply_blob)}B sig={len(sig)}B "
          f"({(t1 - t0) * 1000:.0f} ms, B stateless)")

    t0 = time.perf_counter()
    sess_a = handshake.resolve(handle, reply_blob, sig, ed_b_pub)
    t1 = time.perf_counter()
    sess_b = handshake.session_for_b(ctx_b)
    print(f"resolve: session_id={sess_a.session_id.hex()} "
          f"({(t1 - t0) * 1000:.0f} ms, no KEM re-derivation)")
    assert sess_a.key == sess_b.key, "session keys diverged!"
    print("session keys match: True")

    for msg in (b"hello from A", b"hello from B", b"how copy? over"):
        if msg.startswith(b"hello from B"):
            blob = sess_b.seal(msg)
            got = sess_a.open(blob)
        else:
            blob = sess_a.seal(msg)
            got = sess_b.open(blob)
        assert got == msg, (got, msg)
        print(f"  traffic {msg!r} ({len(blob)}B) ok")
    sess_a.rekey()
    sess_b.rekey()
    assert sess_a.key == sess_b.key
    blob = sess_a.seal(b"post-rekey")
    assert sess_b.open(blob) == b"post-rekey"
    print("rekey + traffic ok")
    print("DEMO OK")


def expect_fail(name, fn):
    try:
        fn()
    except (chacha.AuthenticationError, ValueError) as e:
        print(f"  [reject] {name}: {type(e).__name__}")
        return
    raise SystemExit(f"TAMPER BUG: {name} was NOT rejected")


def fresh_handshake(sA, sB, pkB, ed_b_priv):
    blobs, handle = handshake.propose(sA, pkB, party_a=True, tps=True)
    reply_blob, sig, ctx_b = handshake.reply(sB, list(blobs), party_a=False,
                                             tps=True, ed_sign_key=ed_b_priv)
    return blobs, handle, reply_blob, sig, ctx_b


def cmd_tamper(_args):
    sA, sB, pkB, ed_b_priv, ed_b_pub = make_peers()

    _b, _h, reply_blob, sig, _c = fresh_handshake(sA, sB, pkB, ed_b_priv)
    bad = bytearray(reply_blob)
    bad[-1] ^= 1
    _b2, h2, _r2, _s2, _c2 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    expect_fail("flipped reply byte",
                lambda: handshake.resolve(h2, bytes(bad), sig, ed_b_pub))

    _b3, h3, _r3, _s3, _c3 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    _, wrong_pub = generate_ed25519()
    expect_fail("wrong Ed25519 key",
                lambda: handshake.resolve(h3, reply_blob, sig, wrong_pub))

    _b4, h4, _r4, _s4, _c4 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 1
    expect_fail("flipped signature byte",
                lambda: handshake.resolve(h4, reply_blob, bytes(bad_sig),
                                          ed_b_pub))

    blobs5, h5, _r5, _s5, _c5 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    blobs6, h6, _r6, _s6, _c6 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    expect_fail("replayed reply on 2nd handshake",
                lambda: handshake.resolve(h6, _r5, _s5, ed_b_pub))

    _b7, h7, r7, s7, _c7 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    handshake.resolve(h7, r7, s7, ed_b_pub)  # first OK, consumes handle
    expect_fail("resolve twice on one handle",
                lambda: handshake.resolve(h7, r7, s7, ed_b_pub))

    _b8, stale, r8, s8, _c8 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    stale.ttl = -1.0  # force expiry regardless of clock resolution
    expect_fail("expired handle",
                lambda: handshake.resolve(stale, r8, s8, ed_b_pub))

    blobs9, _h9, _r9, _s9, _c9 = fresh_handshake(sA, sB, pkB, ed_b_priv)
    expect_fail("wrong peer seed",
                lambda: handshake.reply(tmp_master_seed(), list(blobs9),
                                        party_a=False, tps=True,
                                        ed_sign_key=ed_b_priv))

    # Session-level: tamper + replay + reorder.
    _bx, hx, rx, sx, ctxx = fresh_handshake(sA, sB, pkB, ed_b_priv)
    sess_a = handshake.resolve(hx, rx, sx, ed_b_pub)
    sess_b = handshake.session_for_b(ctxx)
    m1 = sess_a.seal(b"one")
    m2 = sess_a.seal(b"two")
    tb = bytearray(m1)
    tb[-1] ^= 1
    expect_fail("tampered traffic byte", lambda: sess_b.open(bytes(tb)))
    expect_fail("out-of-order delivery", lambda: sess_b.open(m2))
    assert sess_b.open(m1) == b"one"
    expect_fail("replayed traffic", lambda: sess_b.open(m1))
    print("TAMPER OK (all rejected)")


def cmd_sizes(_args):
    sA, sB, pkB, _, _ = make_peers()
    blobs, _h = handshake.propose(sA, pkB)
    print(f"TPS blob: {len(blobs[0])} bytes each "
          f"({len(blobs[0]) / 1024:.0f} KiB incl. 221184B pubkey AD)")
    print(f"X25519 pubkey: 32 bytes; Ed25519 sig: 64 bytes")


def main():
    ap = argparse.ArgumentParser(description="PQEP handshake test CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    sub.add_parser("tamper")
    sub.add_parser("sizes")
    args = ap.parse_args()
    {"demo": cmd_demo, "tamper": cmd_tamper, "sizes": cmd_sizes}[args.cmd](args)


if __name__ == "__main__":
    main()

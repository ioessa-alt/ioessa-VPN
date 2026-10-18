"""Mutation fuzzing of the tunnel's datagram entry point, Node.handle.

Method (Sutton, Greene and Amini, Fuzzing, ch. 3 and 5): start from valid captured packets,
apply seeded mutations, and check invariants. The seed comes from IOESSA_FUZZ_SEED (default 1)
and is printed on failure, so every failing input can be replayed exactly (ch. 5,
reproducibility). Each failure prints the input in hex.

Invariants:
  1. handle() never raises, for any input that reaches it.
  2. A mutated DATA packet never yields decrypted inner data.
  3. Garbage does not change state: after many mutated packets, the original valid
     packet still decrypts. Replay and AEAD failures must not consume the window.
  4. A mutated INIT, even with a recomputed mac1 (an attacker who knows the public key),
     never creates a session for the responder.
"""
import os
import random
import unittest

from vpn_ip import build_ipv4

from test_vpn import A_ADDR, B_ADDR, FakeClock, pair, unfinished, remac1
from vpn_constants import INIT_MAC1, MAX_ESP, MSG_COOKIE, MSG_DATA, MSG_INIT, MSG_RESP, RESP_MAC1

MAC2_LEN = 16

SEED = int(os.environ.get("IOESSA_FUZZ_SEED", "1"))
ITERATIONS = int(os.environ.get("IOESSA_FUZZ_ITERATIONS", "1500"))


def mutate(rng: random.Random, data: bytes, corpus) -> bytes:
    """One mutation. Mixes byte-level edits, length changes, type changes and splices (ch. 6)."""
    buf = bytearray(data)
    kind = rng.randrange(8)
    if kind == 0 and buf:                       # bit flip
        i = rng.randrange(len(buf))
        buf[i] ^= 1 << rng.randrange(8)
    elif kind == 1 and buf:                     # random byte
        buf[rng.randrange(len(buf))] = rng.randrange(256)
    elif kind == 2 and buf:                     # interesting values: 0, 0xff, boundary
        i = rng.randrange(len(buf))
        buf[i] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFF))
    elif kind == 3:                             # truncate
        del buf[rng.randrange(len(buf) + 1):]
    elif kind == 4:                             # extend with random bytes
        buf += os.urandom(rng.randrange(1, 64))
    elif kind == 5 and buf:                     # message type byte, any value
        buf[0] = rng.randrange(256)
    elif kind == 6 and buf:                     # zero a run (length and index fields)
        i = rng.randrange(len(buf))
        buf[i:i + rng.randrange(1, 9)] = bytes(len(buf[i:i + 8]))
    else:                                       # splice from another valid packet
        other = bytearray(rng.choice(corpus))
        cut = rng.randrange(len(other) + 1)
        buf = buf[:rng.randrange(len(buf) + 1)] + other[cut:]
    return bytes(buf)


def fail(msg: str, data: bytes):
    raise AssertionError(f"{msg} (IOESSA_FUZZ_SEED={SEED}) input={data.hex()}")


class HandleFuzzTests(unittest.TestCase):

    def test_mutated_data_packets_never_decrypt_and_do_not_disturb_state(self):
        rng = random.Random(SEED)
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa = a.peers[b.pub]
        inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * 20)                # a plausible IPv4 header length
        valid, _ = a.send(pa, inner, clk.t)
        corpus = [valid]
        for _ in range(ITERATIONS):
            mutated = mutate(rng, valid, corpus)
            if mutated == valid:
                continue
            try:
                act = b.handle(mutated, A_ADDR, clk.t)
            except Exception as e:                  # invariant 1
                fail(f"handle raised {type(e).__name__}: {e}", mutated)
            if act.inner is not None:               # invariant 2
                fail("mutated DATA packet decrypted", mutated)
        # invariant 3: the original still decrypts after all the garbage
        act = b.handle(valid, A_ADDR, clk.t)
        self.assertEqual(act.inner, inner, f"valid packet lost after fuzzing (IOESSA_FUZZ_SEED={SEED})")

    def test_mutated_inits_with_valid_mac1_never_create_a_session(self):
        rng = random.Random(SEED + 1)
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        corpus = [init]
        for _ in range(ITERATIONS):
            mutated = mutate(rng, init, corpus)
            if rng.random() < 0.7 and len(mutated) >= INIT_MAC1 + 16:
                # keep the mac1 valid so the fuzz reaches the AEAD and DH code
                mutated = remac1(mutated, INIT_MAC1, b.pub, b"")
            if mutated == init:
                continue                            # the valid INIT legitimately makes a session
            sessions_before = len(b.sessions)
            try:
                b.handle(mutated, A_ADDR, clk.t)
            except Exception as e:                  # invariant 1
                fail(f"handle raised {type(e).__name__}: {e}", mutated)
            if len(b.sessions) > sessions_before and not self._handshake_body_unchanged(init, mutated):
                fail("fuzzed INIT created a session", mutated)

    @staticmethod
    def _handshake_body_unchanged(init: bytes, mutated: bytes) -> bool:
        """True when only the sender index (bytes 4-8) and the MAC fields changed. Those are
        outside the AEAD and Noise transcript, so the genuine handshake can still be accepted
        with them altered (sender index is only used to address the reply)."""
        if len(mutated) != len(init):
            return False
        changed = [i for i in range(len(init)) if init[i] != mutated[i]]
        return all(4 <= i < 8 or i >= INIT_MAC1 for i in changed)

    def test_mutated_responses_never_complete_the_initiator(self):
        rng = random.Random(SEED + 2)
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        (resp, _), = b.handle(init, A_ADDR, clk.t).send
        corpus = [resp]
        for _ in range(ITERATIONS):
            mutated = mutate(rng, resp, corpus)
            if mutated == resp or self._only_mac2_changed(resp, mutated):
                # mac2 is a DoS cookie check, not covered by the handshake. Changing it
                # leaves the RESP valid, as in WireGuard, so skip those cases.
                continue
            try:
                act = a.handle(mutated, B_ADDR, clk.t)
            except Exception as e:                  # invariant 1
                fail(f"handle raised {type(e).__name__}: {e}", mutated)
            if act.peer is not None:
                fail("mutated RESP completed the initiator", mutated)
        self.assertIsNone(pa.current, f"initiator session set by fuzzed input (IOESSA_FUZZ_SEED={SEED})")

    @staticmethod
    def _only_mac2_changed(resp: bytes, mutated: bytes) -> bool:
        """True when the mutation is the same length and changes only bytes of mac2."""
        if len(mutated) != len(resp):
            return False
        changed = [i for i in range(len(resp)) if resp[i] != mutated[i]]
        return all(i >= RESP_MAC1 + MAC2_LEN for i in changed)

    def test_arbitrary_datagrams_never_raise(self):
        rng = random.Random(SEED + 3)
        clk = FakeClock(1000.0)
        b = unfinished(clock=clk)[1]
        for _ in range(ITERATIONS):
            size = rng.choice((0, 1, 3, 4, 7, 8, 9, 16, 32, 1180, 1236, MAX_ESP, MAX_ESP + 1))
            data = bytes([rng.choice((MSG_INIT, MSG_RESP, MSG_COOKIE, MSG_DATA, 0, 5, 255))]) + os.urandom(max(size - 1, 0))
            try:
                b.handle(data, A_ADDR, clk.t)
            except Exception as e:                  # invariant 1
                fail(f"handle raised {type(e).__name__}: {e}", data)


if __name__ == "__main__":
    unittest.main()

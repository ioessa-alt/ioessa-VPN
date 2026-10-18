"""Peers and the Node state machine, plus an in-memory handshake for tests and demos.

The tunnel follows Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel" (NDSS 2017).
"(V-D2)" style notes in the vpn_* modules point at sections of that paper.

What it does:
  * Each side has a long-term Curve25519 static keypair. Peers are identified by public key.
  * One 1-RTT handshake (Noise IK, V-D1 to V-D3) gives two transport keys. Messages are
    INIT (type 1), RESP (type 2), COOKIE reply (type 3) and DATA (type 4), as in V-D.
  * Replay protection for handshakes: an encrypted TAI64N timestamp per peer (V-A).
  * DoS protection: mac1 on every handshake message, mac2 under load, and an encrypted
    cookie reply bound to the source IP (V-C, V-D4, V-D7). No state is kept for
    unauthenticated messages.
  * Roaming (II-A), passive keepalive (VI-E), rekey by time and by message count (VI-B).
  * Optional pre-shared key (V-B). It is off unless the caller passes one.

The transport keeps the hardening from the earlier ESP prototype: a 4-byte aligned padding
trailer, a 64-packet sliding replay window, size bounds before parsing, and the 16-byte
data header authenticated as associated data (the paper leaves the header unauthenticated).

Crypto: X25519 and ChaCha20-Poly1305 come from the `cryptography` package. BLAKE2s comes
from hashlib and HMAC from hmac. The paper's Kdf is HKDF over HMAC-BLAKE2s. The cryptography
package has no BLAKE2s, so Kdf is written out in vpn_crypto.py from the paper's definition.
Nothing in these modules implements a cipher or a MAC itself.
"""
import ipaddress
import os
import secrets
import struct
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_constants import (COOKIE_LEN, COOKIE_LIFETIME, COOKIE_SECRET_TIME, DEFAULT_LOAD_THRESHOLD, FRESHNESS_WINDOW,
                           GLOBAL_HS_CEIL, GLOBAL_HS_FLOOR, GLOBAL_HS_START, GLOBAL_HS_TUNE_PERIOD, HS_FAIL, INIT_LEN,
                           INIT_MAC1, KEEPALIVE_TIMEOUT, KEM_EK_LEN, LOG_BURST, LOG_RATE, MAX_ESP, MSG_COOKIE,
                           MSG_DATA, MSG_INIT, MSG_RESP, Profile, REKEY_ATTEMPT_TIME, REKEY_JITTER_MAX,
                           REKEY_RETRY_CAP, REKEY_TIMEOUT, RESP_LEN, RESP_MAC1, RETRY_JITTER, SRC_INIT_BURST,
                           SRC_INIT_RATE, SRC_TABLE_MAX, STANDARD, TAG_LEN, WIRE_VERSION)
from vpn_errors import ESPError, HandshakeError, RekeyRequired
from vpn_crypto import _is_low_order, _pub_raw, _tai64n, _tai64n_to_unix, check_psk
from vpn_state import TimestampStore
from vpn_handshake import (_check_mac1, _check_mac2, consume_cookie, consume_initiation, consume_response,
                           finish_initiation, InitState, make_cookie_reply, make_initiation, make_response)
from vpn_ip import ANY, BYPASS, DISCARD, Policy, PROTECT, TUNNEL_NET
from vpn_transport import open_data, seal_data, Session


# ------------------------------------------------------------------ peers and node
class Peer:
    """Per-peer state: identity, roaming endpoint, SPD, the sessions (current, previous and
    next, V-C) and the timers (VI)."""

    def __init__(self, pub: bytes, endpoint: Optional[tuple], keepalive: Optional[float]):
        self.pub = pub
        self.endpoint = endpoint
        self.keepalive = keepalive          # None disables keepalives (VI-E)
        self.psk: bytes = b""               # this peer's pre-shared key; set by Node.add_peer
        self.spd: List[Policy] = []
        # Cryptokey routing, inbound half (II, III step 4): after decryption the inner source
        # must fall in these networks. The default allows any source; configure it per peer.
        self.allowed_ips: List[ipaddress.IPv4Network] = [TUNNEL_NET]
        self.current: Optional[Session] = None    # sends and receives
        self.previous: Optional[Session] = None   # still accepts packets in flight (V-C)
        self.next: Optional[Session] = None       # responder side: waits for first data (V-C)
        self.pending: Optional[InitState] = None  # our handshake in progress
        self.attempt_started: Optional[float] = None
        self.last_init_sent: Optional[float] = None
        self.retry_at: Optional[float] = None     # when the pending INIT is sent again
        self.retry_count = 0                      # retransmissions so far in this attempt
        self.rekey_at: Optional[float] = None     # start time of a due rekey, after its random delay
        self.cookie: Optional[bytes] = None       # latest cookie from this peer (V-C)
        self.cookie_at: Optional[float] = None
        self.last_init_ts = bytes(12)             # responder: greatest timestamp seen (V-A)
        self._sent_ts = 0                         # initiator: last timestamp we sent (monotonic)
        self.owe_since: Optional[float] = None    # authenticated data received, not yet answered (VI-E)
        self.kem_pub: Optional[bytes] = None      # peer's static ML-KEM-768 key; no handshake without it

    def route(self, inner: bytes) -> Policy:
        """SPD lookup on the inner destination address. The default is DISCARD."""
        if len(inner) < 20:
            raise ESPError("not IPv4")
        dst = ipaddress.IPv4Address(inner[16:20])
        for p in self.spd:
            if dst in p.net:
                return p
        return Policy(ANY, DISCARD)

    def next_timestamp(self, now_ts: bytes) -> bytes:
        """Strictly increasing per peer, even if the clock steps back (V-A)."""
        val = max(int.from_bytes(now_ts, "big"), self._sent_ts + 1)
        self._sent_ts = val
        return val.to_bytes(12, "big")


@dataclass
class Action:
    """What a received datagram produced: packets to send, decrypted data, and log lines."""
    send: List[Tuple[bytes, tuple]] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    peer: Optional[Peer] = None
    inner: Optional[bytes] = None      # decrypted inner datagram; b"" for a keepalive


class Node:
    """One side of the tunnel: its static key, optional PSK, cookie secret, and its peers."""

    def __init__(self, static_priv: X25519PrivateKey, psk: bytes = b"",
                 clock: Callable[[], float] = time.monotonic,
                 load_threshold: int = DEFAULT_LOAD_THRESHOLD, ts_store: Optional[TimestampStore] = None,
                 rand: Optional[Callable[[], float]] = None,
                 kem_priv: Optional[mlkem.MLKEM768PrivateKey] = None, profile: Profile = STANDARD):
        self._priv = static_priv
        self.pub = _pub_raw(static_priv)
        # Static ML-KEM-768 key. Production loads it from a key file. Without one, a fresh key is
        # made, and no peer can handshake with it until it is configured on their side.
        self._kem_priv = kem_priv if kem_priv is not None else mlkem.MLKEM768PrivateKey.generate()
        self.kem_pub = self._kem_priv.public_key().public_bytes_raw()
        self.profile = profile
        self.psk = psk
        self.clock = clock
        # Source of jitter in [0, 1). Injected by tests so timing is deterministic.
        self.rand = rand if rand is not None else secrets.SystemRandom().random
        self.load_threshold = load_threshold
        self.ts_store = ts_store      # None: replay state is in memory only (lost on restart)
        self.peers: Dict[bytes, Peer] = {}
        self.revoked: set = set()           # keys removed by remove_peer; only the local log uses it
        self.sessions: Dict[int, Tuple[Peer, Session]] = {}   # local index -> session (V-D6 lookup)
        self.pending: Dict[int, Peer] = {}                    # our sender index -> peer
        self._secret = os.urandom(32)                          # cookie secret R_m (V-C)
        self._secret_prev: Optional[bytes] = None
        self._secret_at = clock()
        self._hs_times: Deque[float] = deque()                 # handshake work in the last second
        self._log_tokens = float(LOG_BURST)                    # shared budget for refusal lines
        self._log_at = clock()
        self.refusals_unlogged = 0                             # refusals counted but not printed
        self._src_buckets: "OrderedDict[str, List[float]]" = OrderedDict()   # per-source INIT budget (tokens, last)
        # Global handshake budget (see GLOBAL_HS_START): token bucket plus the tuning counters.
        self.global_hs_rate = GLOBAL_HS_START
        self._gb_tokens = GLOBAL_HS_START
        self._gb_at: Optional[float] = None
        self._gb_window_at: Optional[float] = None
        self._gb_admitted = 0
        self._gb_refused = 0
        self._gb_quiet = 0

    # -- configuration
    def add_peer(self, pub: bytes, endpoint: Optional[tuple] = None,
                 keepalive: Optional[float] = KEEPALIVE_TIMEOUT, kem_pub: Optional[bytes] = None,
                 psk: Optional[bytes] = None) -> Peer:
        """Register a peer. Without its ML-KEM key the peer cannot handshake (fail closed).
        `psk` is this peer's pre-shared key. None uses the node's default PSK (the one from --use-psk)."""
        if len(pub) != 32 or _is_low_order(pub):
            raise ValueError("bad peer public key")
        if kem_pub is not None:
            if len(kem_pub) != KEM_EK_LEN:
                raise ValueError("bad peer ML-KEM key length")
            mlkem.MLKEM768PublicKey.from_public_bytes(kem_pub)     # FIPS 203 key check
        peer = Peer(pub, endpoint, keepalive)
        peer.kem_pub = kem_pub
        peer.psk = self.psk if psk is None else check_psk(psk)
        if self.ts_store is not None:
            peer.last_init_ts = self.ts_store.get(pub)     # restored from the state file
        self.peers[pub] = peer
        self.revoked.discard(pub)           # a re-added key is no longer revoked
        return peer

    def remove_peer(self, pub: bytes) -> None:
        """Revoke a peer: forget its key, pending handshake and every session. Packets that
        arrive on its old session indices are then dropped as unknown. Unknown keys are a no-op."""
        peer = self.peers.pop(pub, None)
        if peer is None:
            return
        self.revoked.add(pub)
        self._drop_pending(peer)
        for slot in ("previous", "current", "next"):
            sess = getattr(peer, slot)
            if sess is not None:
                self.sessions.pop(sess.local_index, None)
                setattr(peer, slot, None)

    # -- helpers
    def _new_index(self) -> int:
        while True:
            idx = secrets.randbelow(2**32 - 1) + 1
            if idx not in self.sessions and idx not in self.pending:
                return idx

    def _cookie_secrets(self, now: float) -> List[bytes]:
        if now - self._secret_at >= COOKIE_SECRET_TIME:
            self._secret_prev, self._secret, self._secret_at = self._secret, os.urandom(32), now
        return [self._secret] + ([self._secret_prev] if self._secret_prev else [])

    def _under_load(self, now: float) -> bool:
        while self._hs_times and now - self._hs_times[0] > 1.0:
            self._hs_times.popleft()
        return len(self._hs_times) >= self.load_threshold

    def _refuse(self, act: Action, msg: str, now: float) -> None:
        """Report a refused inbound datagram. The line is printed only while the shared budget
        (LOG_BURST, refilled at LOG_RATE per second) has a token. Refusals that are not printed
        are counted in refusals_unlogged, so the run total stays correct. One bucket is used,
        not one per source, so memory does not grow with the number of attacker addresses."""
        self._log_tokens = min(float(LOG_BURST), self._log_tokens + max(0.0, now - self._log_at) * LOG_RATE)
        self._log_at = now
        if self._log_tokens >= 1.0:
            self._log_tokens -= 1.0
            act.events.append(msg)
        else:
            self.refusals_unlogged += 1

    def _lifetimes(self) -> dict:
        """Session lifetime fields from the node's profile, for a new Session."""
        return {"limit": self.profile.rekey_after_messages, "rekey_after": self.profile.rekey_after_time,
                "reject_after": self.profile.reject_after_time}

    def _source_budget(self, src: tuple, now: float) -> bool:
        """Token bucket per source address: SRC_INIT_BURST tokens, refilled at SRC_INIT_RATE per second.
        The table is bounded, so memory does not grow with the number of addresses that send."""
        entry = self._src_buckets.get(src[0])
        if entry is None:
            entry = [float(SRC_INIT_BURST), now]
            self._src_buckets[src[0]] = entry
            if len(self._src_buckets) > SRC_TABLE_MAX:
                self._src_buckets.popitem(last=False)
        else:
            self._src_buckets.move_to_end(src[0])
        tokens = min(float(SRC_INIT_BURST), entry[0] + max(0.0, now - entry[1]) * SRC_INIT_RATE)
        entry[1] = now
        if tokens < 1.0:
            entry[0] = tokens
            return False
        entry[0] = tokens - 1.0
        return True

    def _global_hs_budget(self, now: float) -> bool:
        """Admit one INIT (already mac1-checked) if the global token bucket has a token, then tune the rate."""
        if self._gb_at is None:
            self._gb_at = self._gb_window_at = now
        self._gb_tokens = min(self.global_hs_rate, self._gb_tokens + max(0.0, now - self._gb_at) * self.global_hs_rate)
        self._gb_at = now
        self._tune_global_hs(now)
        if self._gb_tokens >= 1.0:
            self._gb_tokens -= 1.0
            self._gb_admitted += 1
            return True
        self._gb_refused += 1
        return False

    def _tune_global_hs(self, now: float) -> None:
        if now - self._gb_window_at < GLOBAL_HS_TUNE_PERIOD:
            return
        if self._gb_refused:
            self._gb_quiet = 0
            self.global_hs_rate = min(GLOBAL_HS_CEIL, self.global_hs_rate * 1.25)
        else:
            self._gb_quiet += 1
            if self._gb_quiet >= 3:
                admitted_rate = self._gb_admitted / GLOBAL_HS_TUNE_PERIOD
                self.global_hs_rate = max(GLOBAL_HS_FLOOR, min(GLOBAL_HS_CEIL, 2 * admitted_rate))
        self._gb_admitted = self._gb_refused = 0
        self._gb_window_at = now

    def _fresh_cookie(self, peer: Peer, now: float) -> Optional[bytes]:
        if peer.cookie is not None and now - (peer.cookie_at or 0.0) < COOKIE_LIFETIME:
            return peer.cookie
        return None

    def _drop_pending(self, peer: Peer) -> None:
        if peer.pending is not None:
            self.pending.pop(peer.pending.sender, None)
        peer.pending = None

    def _set_current(self, peer: Peer, sess: Session) -> None:
        if peer.previous is not None:
            self.sessions.pop(peer.previous.local_index, None)
        peer.previous = peer.current
        peer.current = sess
        self.sessions[sess.local_index] = (peer, sess)

    def _set_next(self, peer: Peer, sess: Session) -> None:
        if peer.next is not None:
            self.sessions.pop(peer.next.local_index, None)
        peer.next = sess
        self.sessions[sess.local_index] = (peer, sess)

    def _promote(self, peer: Peer) -> None:
        """The responder's new session carries authenticated data, so it becomes current (V-C)."""
        if peer.previous is not None:
            self.sessions.pop(peer.previous.local_index, None)
        peer.previous = peer.current
        peer.current = peer.next
        peer.next = None

    def _expire(self, peer: Peer, now: float) -> None:
        """Discard sessions older than three REJECT periods (VI-C)."""
        for slot in ("next", "previous", "current"):
            sess = getattr(peer, slot)
            if sess is not None and now - sess.created >= 3 * sess.reject_after:
                self.sessions.pop(sess.local_index, None)
                setattr(peer, slot, None)

    def _rekey_due(self, sess: Session, now: float) -> bool:
        """Rekey after 120 s or at the message limit, but only once the session has been used (VI-B)."""
        if sess.send_counter == 0:
            return False
        return (now - sess.created >= sess.rekey_after or sess.send_counter >= sess.limit
                or sess.send_bytes >= sess.byte_limit)

    def _data_packet(self, peer: Peer, sess: Session, inner: bytes, now: float) -> bytes:
        pkt = seal_data(sess, inner, now)
        peer.owe_since = None
        return pkt

    # -- handshake initiation (V-D2, VI-D)
    def initiate(self, peer: Peer, now: Optional[float] = None) -> List[Tuple[bytes, tuple]]:
        """Start a handshake attempt with an INIT. Rate-limited to one per REKEY_TIMEOUT (VI-A)."""
        now = self.clock() if now is None else now
        if peer.endpoint is None or peer.kem_pub is None:
            return []
        if peer.last_init_sent is not None and now - peer.last_init_sent < REKEY_TIMEOUT:
            return []
        peer.retry_count = 0                       # a new attempt starts the backoff again
        return self._send_init(peer, now, started=now)

    def _retry_interval(self, retries: int) -> float:
        """Gap before retransmission number `retries` (0 = first retransmission). Doubles from
        REKEY_TIMEOUT up to REKEY_RETRY_CAP, with +/- RETRY_JITTER applied (RFC 7296 2.4)."""
        base = min(REKEY_TIMEOUT * (2 ** retries), REKEY_RETRY_CAP)
        return base * (1.0 + RETRY_JITTER * (2.0 * self.rand() - 1.0))

    def _send_init(self, peer: Peer, now: float, started: float) -> List[Tuple[bytes, tuple]]:
        """Build and send one INIT for the current attempt, and schedule its next retransmission."""
        self._drop_pending(peer)
        sender = self._new_index()
        ts = peer.next_timestamp(_tai64n(time.time_ns()))
        msg, st = make_initiation(self._priv, self.pub, self._kem_priv, peer.pub, peer.kem_pub, peer.psk,
                                  sender, ts, self._fresh_cookie(peer, now))
        peer.pending = st
        peer.attempt_started = started
        peer.last_init_sent = now
        peer.retry_at = now + self._retry_interval(peer.retry_count)
        self.pending[sender] = peer
        return [(msg, peer.endpoint)]

    # -- sending (V-D6)
    def send(self, peer: Peer, inner: bytes, now: Optional[float] = None) -> Optional[Tuple[bytes, tuple]]:
        """Encrypt one inner datagram for `peer`. Returns (packet, endpoint), or None for BYPASS.
        Raises ESPError for DISCARD or no session, and RekeyRequired at the limit."""
        now = self.clock() if now is None else now
        policy = peer.route(inner)
        if policy.action == BYPASS:
            return None
        if policy.action != PROTECT:
            raise ESPError("policy discard")
        if peer.current is None:
            raise ESPError("no session")
        if peer.endpoint is None:
            raise ESPError("no endpoint")
        pkt = self._data_packet(peer, peer.current, inner, now)
        return pkt, peer.endpoint

    # -- timers (VI)
    def poll(self, now: Optional[float] = None) -> List[Tuple[bytes, tuple]]:
        """Run the timers: handshake retransmission, rekey, keepalive. Returns packets to send."""
        now = self.clock() if now is None else now
        out: List[Tuple[bytes, tuple]] = []
        self._cookie_secrets(now)          # rotate on schedule even when no INIT arrives (VI-A, V-C)
        for peer in list(self.peers.values()):
            self._expire(peer, now)
            if peer.pending is not None:
                if now - (peer.attempt_started or now) >= REKEY_ATTEMPT_TIME:
                    self._drop_pending(peer)
                elif peer.retry_at is not None and now >= peer.retry_at:
                    # Retransmit on the backoff schedule. The attempt keeps its start time, so the
                    # total time is bounded by REKEY_ATTEMPT_TIME.
                    peer.retry_count += 1
                    out += self._send_init(peer, now, started=peer.attempt_started or now)
            elif (peer.current is not None and peer.next is None
                  and self._rekey_due(peer.current, now)):
                # A rekey that is due waits a random delay first, so two peers whose timers fire
                # together do not both start an exchange at once (RFC 7296 2.8.1). The wait does
                # not apply to the first handshake, which is sent at once.
                if peer.rekey_at is None:
                    peer.rekey_at = now + REKEY_JITTER_MAX * self.rand()
                if now >= peer.rekey_at:
                    peer.rekey_at = None
                    out += self.initiate(peer, now)
            if (peer.current is not None and peer.endpoint is not None and peer.keepalive
                    and peer.owe_since is not None and now - peer.owe_since >= peer.keepalive):
                try:
                    out.append((self._data_packet(peer, peer.current, b"", now), peer.endpoint))
                except RekeyRequired:
                    pass
        return out

    # -- receiving
    def handle(self, data: bytes, src: tuple, now: Optional[float] = None) -> Action:
        """Process one datagram from `src`. Unauthenticated input gets no reply except the
        cookie reply, which needs a valid mac1 (V-A, V-C)."""
        now = self.clock() if now is None else now
        act = Action()
        if len(data) < 8 or len(data) > MAX_ESP or data[1] != WIRE_VERSION or data[2:4] != bytes(2):
            return act                      # size, version and reserved bytes come before any parsing
        mtype = data[0]
        if mtype == MSG_INIT:
            self._on_init(data, src, now, act)
        elif mtype == MSG_RESP:
            self._on_resp(data, src, now, act)
        elif mtype == MSG_COOKIE:
            self._on_cookie(data, src, now, act)
        elif mtype == MSG_DATA:
            self._on_data(data, src, now, act)
        return act

    def _on_init(self, data: bytes, src: tuple, now: float, act: Action) -> None:
        if len(data) != INIT_LEN or not _check_mac1(data, INIT_MAC1, self.pub):
            return                          # silent: a bad mac1 gets no reply (V-C)
        secs = self._cookie_secrets(now)
        if self._under_load(now) and not _check_mac2(data, INIT_MAC1, secs, src):
            # Under load, answer with a cookie reply and skip the DH work (V-C, V-D7).
            sender = struct.unpack_from("<I", data, 4)[0]
            act.send.append((make_cookie_reply(self.pub, secs[0], src,
                                               data[INIT_MAC1:INIT_MAC1 + TAG_LEN], sender), src))
            act.events.append(f"under load: cookie reply to {src}")
            return
        if not self._global_hs_budget(now):
            # The node-wide handshake budget is used up. Refused before any DH work, silently on the wire.
            self._refuse(act, f"handshake from {src} dropped: global INIT budget used", now)
            return
        if not self._source_budget(src, now):
            # A flood from one address is refused before any DH work. Spoofed sources can evade this,
            # which is why the cookie check above is the main defence under load (V-C).
            self._refuse(act, f"handshake from {src} dropped: per-source INIT budget used", now)
            return
        self._hs_times.append(now)
        try:
            info = consume_initiation(self._priv, self.pub, self.kem_pub, self._kem_priv, data)
        except HandshakeError as e:
            self._refuse(act, f"handshake from {src} rejected: {HS_FAIL} ({e.stage})", now)
            return
        peer = self.peers.get(info.peer_pub)
        if peer is None or peer.kem_pub is None:
            # Nothing is sent back, so the reason is for the local log only (ch.15). No key is printed.
            reason = "revoked peer key" if info.peer_pub in self.revoked else "unknown peer key"
            self._refuse(act, f"handshake from {src} rejected: {reason}", now)
            return
        try:
            info = finish_initiation(info, self._priv, peer.psk)     # the peer's PSK and timestamp
        except HandshakeError as e:
            self._refuse(act, f"handshake from {src} rejected: {HS_FAIL} ({e.stage})", now)
            return
        if abs(time.time() - _tai64n_to_unix(info.timestamp)) > FRESHNESS_WINDOW:
            # The timestamp is wall-clock. A held-back INIT that is replayed late is refused here, even
            # if the responder has no newer INIT on record (open issue 16, model_check_init.py).
            self._refuse(act, f"handshake from {src} rejected: timestamp outside the freshness window", now)
            return
        if info.timestamp <= peer.last_init_ts:
            # Not greater than the last timestamp: a replay or a stale INIT. Silent on the wire.
            self._refuse(act, f"handshake from {src} rejected: stale or replayed timestamp", now)
            return
        if peer.pending is not None and peer.current is not None:
            # Simultaneous rekey (RFC 7296 2.8.1). Our own rekey INIT is in flight, and so is the
            # peer's. Both sides hold both ephemeral public keys, so both pick the same winner with
            # no extra round trip: the INIT with the lower ephemeral key survives. The winner ignores
            # the other INIT and keeps its own exchange. The loser drops its attempt and answers.
            # Neither side keeps a session from the attempt that lost.
            ours = _pub_raw(peer.pending.eph_priv)
            if ours < info.eph_pub:
                act.events.append(f"rekey collision with {src}: our INIT wins, peer's INIT ignored")
                return
            self._drop_pending(peer)
            act.events.append(f"rekey collision with {src}: our INIT loses, answering peer's INIT")
        if self.ts_store is not None:
            # Persist before the timestamp counts and before the RESP is built or returned. If the
            # write fails, nothing changes in memory and no RESP is sent.
            try:
                self.ts_store.save(peer.pub, info.timestamp)
            except OSError:
                self._refuse(act, f"handshake from {src} rejected: state file write failed", now)
                return
        peer.last_init_ts = info.timestamp
        # The endpoint does not move here. The RESP goes back to src, and the endpoint follows
        # the first authenticated packet on the new session (_on_data). A replayed INIT can then
        # never move the endpoint, because the replayer does not hold the session keys.
        sender = self._new_index()
        msg, k_i2r, k_r2i = make_response(info, sender, peer.psk, peer.kem_pub, self._fresh_cookie(peer, now))
        sess = Session(local_index=sender, remote_index=info.sender, send_key=k_r2i,
                       recv_key=k_i2r, created=now, initiator=False, **self._lifetimes())
        self._set_next(peer, sess)
        act.send.append((msg, src))
        act.events.append(f"handshake from {src} accepted; response sent, waiting for first data")

    def _on_resp(self, data: bytes, src: tuple, now: float, act: Action) -> None:
        if len(data) != RESP_LEN or not _check_mac1(data, RESP_MAC1, self.pub):
            return
        peer = self.pending.get(struct.unpack_from("<I", data, 8)[0])
        if peer is None or peer.pending is None:
            return
        st = peer.pending
        try:
            remote, k_i2r, k_r2i = consume_response(st, data)
        except HandshakeError as e:
            self._refuse(act, f"handshake from {src} rejected: {HS_FAIL} ({e.stage})", now)
            return
        self._drop_pending(peer)
        peer.attempt_started = None
        self._set_endpoint(peer, src, act)
        sess = Session(local_index=st.sender, remote_index=remote, send_key=k_i2r,
                       recv_key=k_r2i, created=now, initiator=True, **self._lifetimes())
        self._set_current(peer, sess)
        # Confirm with an empty keepalive. The responder may send data only after it has
        # received transport data from us (V-C), so this lets it promote the new session.
        act.send.append((self._data_packet(peer, sess, b"", now), src))
        act.events.append(f"tunnel up with {src}")

    def _on_cookie(self, data: bytes, src: tuple, now: float, act: Action) -> None:
        if len(data) != COOKIE_LEN:
            return
        peer = self.pending.get(struct.unpack_from("<I", data, 4)[0])
        if peer is None or peer.pending is None:
            return
        try:
            tau = consume_cookie(peer.pending, data)
        except HandshakeError:
            return                          # a forged or misbound cookie is ignored (V-D7)
        peer.cookie = tau
        peer.cookie_at = now
        # No immediate resend. The next INIT goes out when REKEY_TIMEOUT expires (V-F).
        act.events.append(f"cookie from {src} stored")

    def _on_data(self, data: bytes, src: tuple, now: float, act: Action) -> None:
        entry = self.sessions.get(struct.unpack_from("<I", data, 4)[0])
        if entry is None:
            self._refuse(act, f"dropped packet from {src}: unknown index", now)
            return
        peer, sess = entry
        if now - sess.created >= 3 * sess.reject_after:
            # Same age limit as _expire, applied on the receive path too, so an old session stops
            # accepting packets between two timer ticks (VI-C).
            self._refuse(act, f"dropped packet from {src}: session too old", now)
            return
        try:
            inner = open_data(sess, data)
        except ESPError as e:
            self._refuse(act, f"dropped packet from {src}: {e.reason}", now)
            return
        # Packets shorter than an IPv4 header are left to describe() in the caller ("not IPv4").
        if inner and len(inner) >= 20 and not self._source_allowed(peer, inner):
            self._refuse(act, f"dropped packet from {src}: source not allowed", now)
            return
        # Accepted only now: authenticated, not a replay, and the inner source is allowed. Only an
        # accepted packet may move the endpoint (II-A) or promote the new session.
        self._set_endpoint(peer, src, act)
        if sess is peer.next:
            self._promote(peer)
        act.peer = peer
        act.inner = inner
        if inner and peer.owe_since is None:
            peer.owe_since = now            # a keepalive is owed if we have nothing to send

    @staticmethod
    def _source_allowed(peer: Peer, inner: bytes) -> bool:
        """Reverse-path check (II, III step 4): a decrypted packet must claim a source the peer may use."""
        if len(inner) < 20:
            return False
        src = ipaddress.IPv4Address(inner[12:16])
        return any(src in net for net in peer.allowed_ips)

    def check_allowed_ips_disjoint(self) -> None:
        """Raise ValueError if two peers' allowed-IP lists overlap. An overlap means both peers
        may send from the same inner address, so the address does not identify one peer. Peers
        are named by position, not by key, so no key material is printed."""
        peers = list(self.peers.values())
        for i, a in enumerate(peers):
            for j in range(i + 1, len(peers)):
                b = peers[j]
                for na in a.allowed_ips:
                    for nb in b.allowed_ips:
                        if na.overlaps(nb):
                            raise ValueError(f"peers {i + 1} and {j + 1} both allow {na} and {nb}; "
                                             f"an inner address must belong to one peer only")

    def _set_endpoint(self, peer: Peer, src: tuple, act: Action) -> None:
        if peer.endpoint != src:
            if peer.endpoint is not None:
                act.events.append(f"roaming: endpoint {peer.endpoint} -> {src}")
            peer.endpoint = src


# ------------------------------------------------------------------ in-memory pair (tests, demo)
def handshake_local(psk: bytes = b"", clock: Optional[Callable[[], float]] = None,
                    addr_a: tuple = ("127.0.0.1", 1), addr_b: tuple = ("127.0.0.1", 2)) -> Tuple[Node, Node]:
    """Two nodes, each with a fresh static key, that have completed the handshake in memory.
    Node A initiated. Node B has also received A's confirmation, so both can send."""
    clk = clock or time.monotonic
    a = Node(X25519PrivateKey.generate(), psk, clk)
    b = Node(X25519PrivateKey.generate(), psk, clk)
    a.add_peer(b.pub, addr_b, kem_pub=b.kem_pub)
    b.add_peer(a.pub, addr_a, kem_pub=a.kem_pub)
    now = clk()
    (init, _), = a.initiate(a.peers[b.pub], now)
    (resp, _), = b.handle(init, addr_a, now).send
    act = a.handle(resp, addr_b, now)
    for pkt, dst in act.send:
        b.handle(pkt, addr_a, now)
    return a, b

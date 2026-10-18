"""Constants for the tunnel: wire sizes, timers, profiles, labels and env var names."""
import struct
from dataclasses import dataclass


# ------------------------------------------------------------------ constants
MSG_INIT, MSG_RESP, MSG_COOKIE, MSG_DATA = 1, 2, 3, 4       # V-D: msg.type
KEM_EK_LEN = 1184       # ML-KEM-768 public key (encapsulation key), FIPS 203
KEM_CT_LEN = 1088       # ML-KEM-768 ciphertext, FIPS 203
KEM_SEED_LEN = 64       # ML-KEM-768 private key, stored as its 64-byte seed
INIT_LEN = 1236         # type+reserved 4, sender 4, ephemeral 32, ML-KEM ciphertext 1088, static 48, timestamp 28, mac1 16, mac2 16
RESP_LEN = 1180         # type+reserved 4, sender 4, receiver 4, ephemeral 32, ML-KEM ciphertext 1088, empty 16, mac1 16, mac2 16
COOKIE_LEN = 72         # type+reserved 4, receiver 4, salt 32, cookie 32 (16 + tag)
INIT_MAC1 = 1204        # offset of msg.mac1 in INIT; mac2 follows at +16
RESP_MAC1 = 1148        # offset of msg.mac1 in RESP
# Byte 0 is the type, byte 1 the wire version, bytes 2-3 are reserved and must be zero. A datagram
# with another version is dropped before any parsing, so a future protocol can be told apart.
WIRE_VERSION = 2        # v2: per-peer PSK, mixed after the initiator's static key is identified
HS_INIT_HDR = struct.Struct("<BBxxI")      # type, version, reserved, sender (little-endian, V-D1)
HS_RESP_HDR = struct.Struct("<BBxxII")     # type, version, reserved, sender, receiver
HS_COOKIE_HDR = struct.Struct("<BBxxI")    # type, version, reserved, receiver
DATA_HDR = struct.Struct("<BBxxIQ")        # type, version, reserved, receiver index, 64-bit counter (V-D6)
DATA_HDR_LEN = DATA_HDR.size              # 16 bytes, so decryption is in place (V-D6)
TAG_LEN = 16
KEY_LEN = 32
MAX_INNER = 1400        # bounded inner datagram size (MTU minus encapsulation)
MAX_ESP = 1600          # largest datagram accepted at all; larger ones are dropped before parsing
SEQ_MAX = 2**32 - 1     # 32-bit counter space used by this prototype
REKEY_MARGIN = 1024     # rekey this many messages before the counter space runs out
WINDOW = 64             # anti-replay window size in packets (V-D6)
IPV4_NEXT_HEADER = 4    # ESP trailer "next header" = IPv4 (tunnel mode)

# V-A and VI-A timer values from the paper.
REKEY_AFTER_TIME = 120.0        # seconds before a session is replaced (VI-B)
REJECT_AFTER_TIME = 180.0       # after this a session may not send any more (VI-B)
REKEY_TIMEOUT = 5.0             # minimum gap between initiations (VI-A)
REKEY_ATTEMPT_TIME = 90.0       # give up a handshake attempt after this (VI-A)
REKEY_RETRY_CAP = 20.0          # largest gap between INIT retransmissions; gaps double from REKEY_TIMEOUT (RFC 7296 2.4)
RETRY_JITTER = 0.2              # each retransmission gap varies by +/- this fraction (fleet desynchronisation)
REKEY_JITTER_MAX = 5.0          # a due rekey waits a random 0..this many seconds before its INIT (RFC 7296 2.8.1)
KEEPALIVE_TIMEOUT = 10.0        # default passive keepalive period (VI-A)
COOKIE_SECRET_TIME = 120.0      # the cookie secret rotates this often (V-C)
COOKIE_LIFETIME = 120.0         # mac2 is zero when the cookie is older than this (V-D4)
# Paper: 2^60 messages. This prototype keeps its own, stricter 2^32 limit (see THREAT_MODEL.md).
REKEY_AFTER_MESSAGES = SEQ_MAX - REKEY_MARGIN
REKEY_AFTER_BYTES = 1 << 30     # inner plaintext bytes per session before a rekey (SA lifetime by volume)


@dataclass(frozen=True)
class Profile:
    """Session key lifetime. `standard` uses the paper's timers. `strict` replaces session keys
    four times as often, so a stolen session key exposes less traffic. The handshake costs about
    0.4 ms of CPU either way, so the choice is about exposure, not speed."""
    name: str
    rekey_after_time: float      # seconds before a used session is replaced
    reject_after_time: float     # after this a session may not send any more
    rekey_after_messages: int    # packets before a session is replaced


STANDARD = Profile("standard", REKEY_AFTER_TIME, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES)
STRICT = Profile("strict", 30.0, 45.0, 2**24)
PROFILES = {p.name: p for p in (STANDARD, STRICT)}
DEFAULT_LOAD_THRESHOLD = 50     # handshake operations per second that count as "under load" (V-C)
# Global handshake budget (open issue 1). Counts only INITs that pass mac1, so random junk costs nothing.
# It starts at GLOBAL_HS_START per second and tunes itself every GLOBAL_HS_TUNE_PERIOD seconds:
# up by 25% in any window that refused something, down to twice the admitted rate after three quiet
# windows. It stays between GLOBAL_HS_FLOOR and GLOBAL_HS_CEIL. The ceiling caps CPU under a flood.
GLOBAL_HS_START = 200.0
GLOBAL_HS_FLOOR = 50.0
GLOBAL_HS_CEIL = 2000.0
GLOBAL_HS_TUNE_PERIOD = 10.0
FRESHNESS_WINDOW = 180.0       # seconds: an INIT timestamp more than this far from our wall clock is refused
LOG_BURST = 20                 # refused inbound datagrams that may be printed at once (ch.10: bounded output)
LOG_RATE = 5.0                  # sustained printed refusals per second, shared by all sources
SRC_INIT_RATE = 2.0             # INIT messages per second accepted from one source address (after mac1)
SRC_INIT_BURST = 20             # burst allowed from one source before the rate applies
SRC_TABLE_MAX = 4096            # source buckets kept; the least recently used is evicted

CONSTRUCTION = b"Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s"        # V-D1, plus the static ML-KEM-768 step
CONSTRUCTION_PSK = b"NoisePSK_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s"  # V-D1, used when a PSK is set
IDENTIFIER = b"WireGuard v0 zx2c4 Jason@zx2c4.com"         # V-D1, 34 bytes
LABEL_MAC1 = b"mac1----"       # label for the mac1 key (WireGuard reference protocol)
LABEL_COOKIE = b"cookie--"     # label for the cookie-reply key (WireGuard reference protocol)
LABEL_I2R = b"ioessa transport key I->R"   # per-direction labels for transport keys (kept
LABEL_R2I = b"ioessa transport key R->I"   # from the earlier prototype's HKDF labels)
ZERO_NONCE = bytes(12)         # V-D1 Aead nonce with counter 0; every key is used once
HS_FAIL = "handshake failed"   # one generic reason for every handshake failure (no oracle)

KEY_ENV = "IOESSA_VPN_PRIVATE_KEY"          # local static private key, base64
KEY_FILE_ENV = "IOESSA_VPN_PRIVATE_KEY_FILE"
KEM_KEY_ENV = "IOESSA_VPN_KEM_KEY"                # local static ML-KEM-768 seed, base64
KEM_KEY_FILE_ENV = "IOESSA_VPN_KEM_KEY_FILE"
PEER_ENV = "IOESSA_VPN_PEER_PUBLIC_KEY"     # peer static public key(s), base64, comma separated
PSK_ENV = "IOESSA_VPN_PSK"                  # optional pre-shared key, hex, used only with --use-psk
STATE_FILE_ENV = "IOESSA_VPN_STATE_FILE"    # per-peer handshake timestamps, kept across restarts (default below)
STATE_TAG_KEY = "_mac"                      # the reserved key that holds the state file's integrity tag
LABEL_STATE = b"ioessa state file integrity"
TS_LEN = 12                                 # TAI64N timestamp length (V-A)

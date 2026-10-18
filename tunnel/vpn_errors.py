"""Exceptions raised by the tunnel core."""
from vpn_constants import HS_FAIL


class ESPError(Exception):
    """A packet was dropped. `reason` is a short, non-sensitive label."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class RekeyRequired(Exception):
    """The session is near its message limit or too old. Run the handshake again."""


class HandshakeError(Exception):
    """A handshake step failed. `reason` is always HS_FAIL, which is all the wire carries. `stage`
    names the step for the local log only (open issue 18), so an operator can tell a wrong key from
    a bad transcript. Nothing sends `stage` to the peer."""

    def __init__(self, reason: str = HS_FAIL, stage: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.stage = stage


# ------------------------------------------------------------------ restart state (V-A)
class StateFileError(Exception):
    """The state file cannot be used. The server must not start with it; it must not reset it."""

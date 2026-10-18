"""Explicit-state model check of the INIT timestamp rule (Baier and Katoen, Principles of Model
Checking, ch. 2 and 3: transition systems, safety properties, counterexample traces).

The model is finite. Time runs 0..T_MAX. The initiator sends INIT messages with the current
time as the timestamp, up to SENDS of them. An intruder can capture every message, deliver any
captured message any number of times, and drop any message. The responder applies the rule in
`Node._on_init` (vpn_node.py): accept a timestamp only if it is greater than the last one
accepted from this peer, and then store it.

Properties (checked over every reachable state):
  replay_safety: no timestamp is accepted twice.
  freshness:     every accepted timestamp is at most WINDOW seconds old when accepted.

The current rule has no freshness check, so `freshness` is expected to fail. The counterexample
is a suppress-replay (Gong, cited in Boyd and Mathuria 1.5): a captured INIT is held back, then
replayed much later. OPEN_ISSUES item 16 rates this Low. `window=` builds a variant with a
freshness check, and the model confirms that it removes the counterexample.
"""
from collections import deque
from typing import Optional, Tuple

T_MAX = 8      # time domain 0..T_MAX
SENDS = 2      # genuine INITs the initiator sends
WINDOW = 2     # freshness window in seconds, for the variant


# State: (now, last_ts, sends_left, network, accepted)
#   network:  sorted tuple of timestamps the intruder has captured (replayable)
#   accepted: tuple of (ts, accepted_at) for every INIT the responder accepted
State = Tuple[int, int, int, Tuple[int, ...], Tuple[Tuple[int, int], ...]]


def initial() -> State:
    return (0, 0, SENDS, (), ())


def successors(state: State, window: Optional[int]):
    """Yield (action label, next state) for every enabled action."""
    now, last_ts, sends_left, network, accepted = state
    if now < T_MAX:
        yield "tick", (now + 1, last_ts, sends_left, network, accepted)
    if sends_left > 0:
        # The intruder captures the new message. Capturing also covers the case where it is dropped.
        yield f"send {now}", (now, last_ts, sends_left - 1,
                              tuple(sorted(set(network) | {now})), accepted)
    for ts in network:
        # Deliver a captured INIT (intruder replay). The message stays captured.
        if ts > last_ts and (window is None or now - ts <= window):
            yield f"deliver {ts} at {now}", (now, ts, sends_left, network,
                                             accepted + ((ts, now),))
        else:
            yield f"deliver {ts} at {now} (refused)", state


def check(window: Optional[int] = None):
    """Breadth-first search. Returns (violations, states_seen), where violations maps a property
    name to the shortest trace that breaks it."""
    violations = {}
    seen = {initial()}
    parent = {initial(): None}
    queue = deque([initial()])
    while queue:
        state = queue.popleft()
        accepted = state[4]
        ts_list = [ts for ts, _ in accepted]
        if len(set(ts_list)) != len(ts_list) and "replay_safety" not in violations:
            violations["replay_safety"] = trace(parent, state)
        for ts, at in accepted:
            if at - ts > WINDOW and "freshness" not in violations:
                violations["freshness"] = trace(parent, state)
        for label, nxt in successors(state, window):
            if nxt not in seen:
                seen.add(nxt)
                parent[nxt] = (state, label)
                queue.append(nxt)
    return violations, len(seen)


def trace(parent, state):
    steps = []
    while parent[state] is not None:
        prev, label = parent[state]
        steps.append(label)
        state = prev
    return list(reversed(steps))


if __name__ == "__main__":
    for name, w in (("current rule", None), (f"freshness window {WINDOW}s", WINDOW)):
        violations, n = check(w)
        print(f"{name}: {n} states")
        for prop in ("replay_safety", "freshness"):
            if prop in violations:
                print(f"  {prop}: VIOLATED by {' -> '.join(violations[prop])}")
            else:
                print(f"  {prop}: holds")

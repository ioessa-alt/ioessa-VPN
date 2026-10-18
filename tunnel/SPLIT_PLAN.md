# Plan: splitting vpn_core.py (done)

Status: done 2026-10-17, steps 1 to 7, each ending with all suites green. Differences from the plan below:

- The `test_vpn.py:704` and `test_state.py:109` patches moved in step 5, not step 4: `Node` stays in
  `vpn_core` until step 5, so patching `vpn_core` is still right during step 4.
- `CONSTRUCTION_PSK` was deleted (unused).
- Follow-up, same day: every test imports from the new modules (names unqualified, as most tests already
  did; `cryptography` names such as `Encoding` are imported directly), `test_state.py` patches
  `vpn_state.os.replace` and `vpn_state.os.fsync`, and `vpn_core.py` is gone. Its protocol overview is now the
  docstring of `vpn_node.py`. The key-literal test in `test_vpn.py` scans every core module.

Original plan follows. `vpn_core.py` was about 1,600 lines and mixes constants, errors, crypto, key
files, replay state, the handshake, transport, IP helpers, the Node state machine, and the TUN classes.
Splitting it makes each part easier to review, and it lets two sessions work on different parts without
conflicts. Do it after the protocol stops changing (see OPEN_ISSUES, item 22).

## 1. Target layout

Dependencies flow downward. Nothing imports a module above it.

```
vpn_constants.py   constants, Profile, PROFILES, label strings, env var names          (no project imports)
vpn_errors.py      ESPError, RekeyRequired, HandshakeError, StateFileError               (vpn_constants for HS_FAIL)
vpn_crypto.py      _h, _mac, _hmac_b2s, _kdf, _aead_seal/_open, _encaps/_decaps, _dh,   (constants, errors)
                   _pub_raw, _is_low_order, _tai64n, _tai64n_to_unix, key encode/decode,
                   new_private_key, generate_keypair, generate_kem_keypair, check_psk
vpn_keyfiles.py    load_static_private, load_kem_private, load_peer_entries,              (crypto, constants)
                   load_peer_publics, load_psk, check_key_age, CREATED_SUFFIX,
                   _check_key_file_mode, _check_windows_acl, _parse_icacls
vpn_state.py       TimestampStore, _atomic_write, state_key, default_state_path          (crypto, errors)
vpn_handshake.py   _init_chain, _mac1_key, _cookie_key, _check_mac1/_mac2, _header_ok,    (crypto, constants, errors)
                   _check_shape, InitState, InitInfo, make_initiation, consume_initiation,
                   finish_initiation, make_response, consume_response, make_cookie_reply,
                   consume_cookie, _transport_keys
vpn_ip.py          Policy, PROTECT/BYPASS/DISCARD, ANY, TUNNEL_NET, build_ipv4,          (constants)
                   parse_ipv4, describe
vpn_transport.py   ReplayWindow, Session, _data_nonce, seal_data, open_data               (crypto, constants, errors)
vpn_node.py        Peer, Action, Node, handshake_local                                   (everything above)
vpn_tun.py         TunDevice, QueueTun                                                    (nothing)
vpn_core.py        shim: re-exports every name above (see section 3)
```

Line ranges in the current `vpn_core.py` (as of 2026-10-17) are the starting point for the move. Re-check
them before cutting, because other sessions edit this file.

## 2. Gotchas found while planning

1. **Patch targets move with the code.** Tests patch names that `Node` looks up at call time:
   - `test_vpn.py:704`: `mock.patch("vpn_core.consume_initiation")` must become `vpn_node.consume_initiation`.
   - `test_state.py:109`: `mock.patch("vpn_core.make_response")` must become `vpn_node.make_response`.
   A patch on the shim does nothing, because `Node` calls the name from its own module.
2. **`os` patches stay valid.** `test_state.py` patches `vpn_core.os.replace` and `vpn_core.os.fsync`. Those
   patch the shared `os` module, so they still work after the move, but a test that only wants to affect
   `_atomic_write` should patch `vpn_state.os` instead, to avoid side effects.
3. **Private names are imported by tests.** `test_vpn.py`, `test_randomness.py`, `test_hardening.py` and
   `analysis/` use `_mac`, `_mac1_key`, `_cookie_key`, `_check_mac1`, `_kdf`, `_dh`, `_is_low_order`, `_tai64n` and
   others. The shim must re-export them explicitly. `from x import *` skips names starting with `_`.
4. **Windows ACL and key-mode checks are tested by patching `vpn_core._check_windows_acl` and
   `_check_key_file_mode`** (`test_hardening.py:235,246`). Those patches must follow the move to `vpn_keyfiles`.
5. **`_check_key_file_mode` is called with `posix=` and `stat=` arguments** in tests. Keep the signature.
6. **`CONSTRUCTION_PSK` is no longer used** (the PSK moved after the static key). Delete it when the constants
   move, and check nothing refers to it first (`grep CONSTRUCTION_PSK`).
7. **Circularity risk:** `vpn_state.state_key` uses `_h` from crypto, and `vpn_keyfiles.check_key_age` is used
   by the server. Keep `state_key` and `default_state_path` out of `vpn_keyfiles`, as listed above.
8. **Test helpers import from `test_vpn`** (`pair`, `unfinished`, `remac1`, `FakeClock`). Those helpers import
   from `vpn_core`. They keep working through the shim, but after the move they should import from the new
   modules, so the shim can be removed later.

## 3. The shim

`vpn_core.py` keeps every name it exports today, so the server, client, analysis tools and tests keep
working unchanged:

```python
# vpn_core.py: compatibility shim. The code lives in the vpn_* modules listed in SPLIT_PLAN.md.
from vpn_constants import *        # noqa: F401,F403
from vpn_constants import Profile, PROFILES, STANDARD, STRICT   # explicit: some are not in __all__
from vpn_errors import ESPError, RekeyRequired, HandshakeError, StateFileError
from vpn_crypto import _h, _mac, _kdf, _dh, _tai64n, ...       # every name, explicitly, including _private
...
```

Write the explicit list from `grep -o` of the names the tests and tools use. A missing name shows up as an
`ImportError` in the test run, which makes it easy to find. Keep the shim until the tests import the new
modules directly, then remove it in a separate change.

## 4. Order of work (each step ends with all suites green)

1. Add `vpn_constants.py` and `vpn_errors.py`. Point `vpn_core` at them through the shim. Run the suites.
2. Add `vpn_crypto.py`. Same check.
3. Add `vpn_keyfiles.py`, `vpn_state.py`. Move the patch targets from section 2 (items 1 and 4) in the same change.
4. Add `vpn_handshake.py`, `vpn_ip.py`, `vpn_transport.py`. Move `test_vpn.py:704` and `test_state.py:109`.
5. Add `vpn_node.py` and `vpn_tun.py`. Move the rest of the patch targets.
6. Point `vpn_server.py`, `vpn_client.py`, `peer_reload.py`, `tun_linux.py`, `tun_windows.py` and the analysis
   tools at the new modules where it is simple. Leave the shim in place.
7. Check that `analysis/` and the root `README.md` still describe the right files. Update `SPLIT_PLAN.md` to say "done".

After each step: `python -m unittest` in `tunnel\` (287 tests at last count), `python -m unittest discover -s
analysis -p "test_*.py"` (28), and `python -m unittest test_web test_fuzz_web test_web_accounts test_web_tls` in the
project root. If a step breaks a test, stop, fix that step, and don't carry on.

## 5. What not to change in the same step

Do not change behaviour, names, wire format or error text while moving code. Each step is a pure move. Any
behaviour change goes in a separate change, after the split.

## 6. Who else edits these files

`peer_reload.py` and `test_reload.py` belong to another session (ioessa-vpn-87). Tell that session before the
move, because they import `load_peer_entries` from `vpn_core`. Check with `ListAgents` that nothing else is
editing `vpn_core.py` before step 1.

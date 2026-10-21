# Audit request: ioessa tunnel prototype

Prepared 2026-10-17. Send the message in section 2 to two or three firms from section 3, attach the zip
and manifest from this folder only after an NDA or a quote is agreed (if the firm asks for one), and
compare the quotes. Fill in the parts in [brackets].

## 1. Before you send

1. Unpack the zip somewhere else and run `python -m unittest` in it: it should report 294 tests, OK.
   That proves the package is complete.
2. Decide the budget and the date by which you need the report.
3. Pick the contact address you will use for the audit. `SECURITY.md` uses GitHub reporting and has no
   address, so this needs one of its own.

## 2. Message to send

> Subject: Quote request: security review of a small VPN handshake prototype (Python, ~1,600 lines)
>
> Hello,
>
> I am looking for a quote for a cryptographic and security review of a VPN tunnel prototype.
>
> - What it is: a WireGuard-style tunnel in Python. The handshake is Noise IK with an added ML-KEM-768 step
>   (hybrid post-quantum) and an optional per-peer pre-shared key. Transport is ChaCha20-Poly1305 with a
>   replay window. Primitives come from the `cryptography` package; nothing implements a cipher itself.
> - Size: about 1,600 lines for the protocol core, about 900 more for the server, client and key tools,
>   including comments. 294 unit tests, a fuzz test and a small model check are included.
> - Scope document: attached (`AUDIT_SCOPE.md`). It has the message layouts, the key schedule, the claims
>   to check, the known open items, and four specific questions.
> - Out of scope: a Linux TUN backend, a demo web UI, and a packet-analysis toolkit.
> - Deliverables: a written report with severity-rated findings and fix recommendations, and a retest
>   after fixes.
> - Status: a learning prototype, not deployed, not interoperable with WireGuard. No real traffic depends
>   on it yet.
>
> Could you tell me your availability, an estimate of effort and cost, and whether you need an NDA before
> receiving the code?
>
> Thank you,
> [your name]
> [contact address]

## 3. Firms to ask

These firms publish cryptographic or protocol audit reports. Check each one's current services and
contact page before you write. This list is from general knowledge, not a recommendation, and is not
checked against current offerings.

- NCC Group (Cryptography Services)
- Trail of Bits
- Cure53
- Least Authority
- X41 D-Sec
- Quarkslab
- Radically Open Security (a non-profit; often cheaper for small projects)

For an open-source project, OSTIF (Open Source Technology Improvement Fund) can arrange and sometimes fund
an audit.

## 4. What to expect

- Effort: a scope this size is usually quoted as a short engagement of days to a few weeks, not months.
  That is an estimate; only the quotes will tell.
- The firm may ask to change the scope (for example to add the server loop or drop the questions).
  Update `tunnel\AUDIT_SCOPE.md` and make a new package if the code changes.
- Keep the report outside the project folder until the findings are fixed, as `AUDIT_SCOPE.md` asks.

## 5. The package

| File | What it is |
|---|---|
| `ioessa-tunnel-audit-2026-10-21.zip` | `tunnel\` without `analysis\` and caches: code, tests, scope, reviews |
| `MANIFEST.sha256` | SHA-256 of every file in the zip; the auditor cites this version |

If you change any file in `tunnel\` before the audit starts, the package is out of date: ask Claude to
make a new one.

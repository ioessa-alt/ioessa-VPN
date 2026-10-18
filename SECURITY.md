# Security policy

## Status

ioessa-VPN is a learning prototype. The tunnel (`tunnel\`) is not audited and must not protect real
traffic (see `tunnel\AUDIT_SCOPE.md`). The web UI in this folder is a simulation: it creates no tunnel
and routes no traffic. Reports are still welcome, because finding the flaws is the point of the project.

## Supported versions

Only the current code in this repository. There are no releases and no backports.

## How to report a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. The report is visible only to the maintainers and to you.

Please do not open a public issue, pull request or discussion for a security problem.

A useful report says:

- which part is affected (the handshake, transport, key or state files, the server or client loop, the web UI);
- the steps or the input that shows the problem, and what you expected instead;
- the file and line, if you know them;
- whether you want to be credited, and under what name.

## What happens next

This is a one-person hobby project, so everything below is best effort, not a promise.

- You get an acknowledgement, usually within 7 days.
- The report is confirmed or declined, with the reason.
- A fix is made in the open once it is ready, and the advisory is published through GitHub with credit to
  you unless you ask otherwise.
- If a fix takes longer than 90 days from your report, you may publish your findings. Please say so in the
  report thread first.

## Scope

In scope: everything in this repository, the tunnel prototype most of all. Known, accepted limits are
listed in `tunnel\OPEN_ISSUES.md` and `tunnel\THREAT_MODEL.md`. A report on one of those is welcome if it
shows a worse effect than the one described there.

Out of scope: problems in Python, the `cryptography` package or Wintun themselves (report those upstream),
and attacks that need control of the machine running the prototype.

There is no bug bounty.

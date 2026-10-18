"""Run vpn_server or vpn_client with the capture hook (tap.py) switched on.

    python analysis/capture_run.py --capture-dir DIR server --port 45500 --idle-timeout 30
    python analysis/capture_run.py --capture-dir DIR client --port 45500 --packets 3
    IOESSA_VPN_CAPTURE_DIR=DIR python analysis/capture_run.py client --port 45500

With neither --capture-dir nor IOESSA_VPN_CAPTURE_DIR, the script runs exactly as it does
without this file. Every other option is passed to the script unchanged. Key handling is
unchanged too: keys still come from IOESSA_VPN_PRIVATE_KEY and the other documented settings.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, TUNNEL)

from tap import ENV_CAPTURE_DIR, CaptureSink, install  # noqa: E402


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Run the tunnel server or client with the capture hook")
    ap.add_argument("role", choices=["server", "client"])
    ap.add_argument("--capture-dir", default=None,
                    help=f"write outer.pcap and inner.pcap here (default: ${ENV_CAPTURE_DIR}; off when unset)")
    ns, rest = ap.parse_known_args(argv)
    if rest[:1] == ["--"]:
        rest = rest[1:]
    capture_dir = ns.capture_dir or os.environ.get(ENV_CAPTURE_DIR)

    if ns.role == "server":
        import vpn_server as mod
    else:
        import vpn_client as mod
    sys.argv = [mod.__file__, *rest]

    if not capture_dir:
        mod.main()
        return
    sink = CaptureSink(capture_dir)
    install(mod, sink)
    try:
        mod.main()
    finally:
        sink.close()


if __name__ == "__main__":
    main()

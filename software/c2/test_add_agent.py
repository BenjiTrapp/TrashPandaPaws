#!/usr/bin/env python3
"""
Test agent — registers a beacon with the C2 server and keeps it alive.
Used by test_add_agent.sh / test_add_agent.ps1.

Usage:
  python test_add_agent.py --host 127.0.0.1 --port 8443 --key <b64>
  python test_add_agent.py --key <b64>   # --key is required; the server's key
"""

import argparse
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.c2.beacon import Beacon, decode_key


def main():
    parser = argparse.ArgumentParser(description="Raccoon C2 — Test Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Server IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Server port (default: 8443)")
    parser.add_argument("--key", default="",
                        help="Base64 AES-256-GCM key (required; the server's)")
    parser.add_argument("--interval", type=int, default=5, help="Beacon interval in seconds (default: 5)")
    parser.add_argument("--jitter", type=int, default=10, help="Jitter percent (default: 10)")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS")
    args = parser.parse_args()

    proto = "https" if args.ssl else "http"
    callback_url = f"{proto}://{args.host}:{args.port}/api/v1/beacon"

    # The key is validated by the beacon itself, which names the problem
    # and never the value; this only turns its refusal into a clean exit.
    enc_key = args.key
    try:
        decode_key(enc_key)
    except ValueError as exc:
        refusal = str(exc)
    else:
        refusal = None
    if refusal:
        print(f"[!] {refusal}")
        sys.exit(1)

    config = {
        "c2": {
            "beacon_interval_seconds": args.interval,
            "jitter_percent": args.jitter,
            "encryption_key": enc_key,
            "https": {
                "enabled": True,
                "callback_url": callback_url,
                "verify_ssl": False,
            },
            "dns": {
                "enabled": False,
                "domain": "",
                "resolver": "8.8.8.8",
            },
        }
    }

    beacon = Beacon(config)
    beacon.start()

    shutdown = False

    def handle_sig(sig, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    while not shutdown:
        time.sleep(0.5)

    beacon.stop()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test server for Raccoon Implant cover identities.
Starts Cisco Phone and/or HP Printer covers on localhost for manual testing.

Usage:
  python -m software.tests.test_server                  # both covers
  python -m software.tests.test_server --cover cisco    # Cisco only
  python -m software.tests.test_server --cover printer  # HP Printer only
  python -m software.tests.test_server --cover both     # both (default)

All services bind to 127.0.0.1 with non-privileged ports (no root needed).
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)

CISCO_CONFIG = {
    "device": {
        "model": "Cisco IP Phone 7960",
        "firmware": "P0S3-08-12-00",
    },
    "cover": {
        "cisco_phone": {
            "http_port": 8080,
            "sip_port": 15060,
            "rtp_port": 15000,
        },
    },
    "notifications": {"enabled": False},
}

PRINTER_CONFIG = {
    "cover": {
        "hp_printer": {
            "http_port": 8081,
            "pjl_port": 19100,
            "lpd_port": 10515,
            "ipp_port": 10631,
            "snmp_port": 10161,
            "telnet_port": 10023,
        },
    },
    "notifications": {"enabled": False},
}

BANNER = r"""
 ____                                  ___                 _             _
|  _ \ __ _  ___ ___ ___   ___  _ __  |_ _|_ __ ___  _ __ | | __ _ _ __ | |_
| |_) / _` |/ __/ __/ _ \ / _ \| '_ \  | || '_ ` _ \| '_ \| |/ _` | '_ \| __|
|  _ < (_| | (_| (_| (_) | (_) | | | | | || | | | | | |_) | | (_| | | | | |_
|_| \_\__,_|\___\___\___/ \___/|_| |_||___|_| |_| |_| .__/|_|\__,_|_| |_|\__|
                                                      |_|
                        Cover Identity Test Server
"""


def print_cisco_endpoints():
    print("\n  ┌─────────────────────────────────────────────────────────┐")
    print("  │  CISCO IP PHONE 7960                                   │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print("  │  HTTP Admin     http://127.0.0.1:8080                  │")
    print("  │  SIP Listener   udp://127.0.0.1:15060                  │")
    print("  │  RTP Audio      udp://127.0.0.1:15000                  │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print("  │  Test commands:                                        │")
    print("  │    curl http://127.0.0.1:8080                          │")
    print("  │    curl -X POST -d 'username=admin&password=cisco'  \\  │")
    print("  │         http://127.0.0.1:8080                          │")
    print("  │    # SIP OPTIONS probe:                                │")
    print("  │    echo -ne 'OPTIONS sip:test@127.0.0.1 SIP/2.0\\r\\n'  │")
    print("  │      | nc -u -w1 127.0.0.1 15060                      │")
    print("  └─────────────────────────────────────────────────────────┘")


def print_printer_endpoints():
    print("\n  ┌─────────────────────────────────────────────────────────┐")
    print("  │  HP COLOR LASERJET PRO MFP M478                       │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print("  │  HTTP Admin     http://127.0.0.1:8081       (401)      │")
    print("  │  JetDirect/PJL  tcp://127.0.0.1:19100                  │")
    print("  │  LPD            tcp://127.0.0.1:10515                  │")
    print("  │  CUPS/IPP       tcp://127.0.0.1:10631                  │")
    print("  │  SNMP           udp://127.0.0.1:10161                  │")
    print("  │  Telnet         tcp://127.0.0.1:10023                  │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print("  │  Test commands:                                        │")
    print("  │    curl -v http://127.0.0.1:8081                       │")
    print("  │    curl -u admin:password http://127.0.0.1:8081        │")
    print("  │    echo '@PJL INFO PRODINFO' | nc 127.0.0.1 19100      │")
    print("  │    echo '@PJL INFO STATUS' | nc 127.0.0.1 19100        │")
    print("  │    curl http://127.0.0.1:10631                         │")
    print("  │    telnet 127.0.0.1 10023                              │")
    print("  └─────────────────────────────────────────────────────────┘")


def print_nmap_hint(cover: str):
    print("\n  Nmap scan commands:")
    if cover in ("cisco", "both"):
        print("    nmap -sV -p 8080,15060 127.0.0.1")
    if cover in ("printer", "both"):
        print("    nmap -sV -p 8081,19100,10515,10631,10023 127.0.0.1")
        print("    nmap -sU -p 10161 127.0.0.1")


def main():
    parser = argparse.ArgumentParser(
        description="Raccoon Implant — Cover Identity Test Server"
    )
    parser.add_argument(
        "--cover",
        choices=["cisco", "printer", "both"],
        default="both",
        help="Which cover to start (default: both)",
    )
    parser.add_argument(
        "--slack-webhook",
        default="",
        help="Slack webhook URL for testing notifications",
    )
    parser.add_argument(
        "--discord-webhook",
        default="",
        help="Discord webhook URL for testing notifications",
    )
    parser.add_argument(
        "--teams-webhook",
        default="",
        help="Microsoft Teams webhook URL for testing notifications",
    )
    args = parser.parse_args()

    print(BANNER)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Notification setup
    if args.slack_webhook or args.discord_webhook or args.teams_webhook:
        notify_cfg = {
            "notifications": {
                "enabled": True,
                "slack": {"enabled": bool(args.slack_webhook), "webhook_url": args.slack_webhook},
                "discord": {"enabled": bool(args.discord_webhook), "webhook_url": args.discord_webhook},
                "teams": {"enabled": bool(args.teams_webhook), "webhook_url": args.teams_webhook},
            }
        }
        from software.notifications import init_notifier
        notifier = init_notifier(notify_cfg)
        CISCO_CONFIG["notifications"] = notify_cfg["notifications"]
        PRINTER_CONFIG["notifications"] = notify_cfg["notifications"]
        print("  Notifications: enabled")
        if args.slack_webhook:
            print(f"    Slack:   {args.slack_webhook[:50]}...")
        if args.discord_webhook:
            print(f"    Discord: {args.discord_webhook[:50]}...")
        if args.teams_webhook:
            print(f"    Teams:   {args.teams_webhook[:50]}...")

    covers = []

    if args.cover in ("cisco", "both"):
        from software.cover.cisco_phone import CiscoCover
        cisco = CiscoCover(CISCO_CONFIG)
        cisco.start()
        covers.append(cisco)
        print_cisco_endpoints()

    if args.cover in ("printer", "both"):
        from software.cover.hp_printer import HPPrinterCover
        printer = HPPrinterCover(PRINTER_CONFIG)
        printer.start()
        covers.append(printer)
        print_printer_endpoints()

    print_nmap_hint(args.cover)

    print("\n  Press Ctrl+C to stop.\n")

    shutdown = False

    def handle_sig(sig, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    while not shutdown:
        time.sleep(0.5)

    print("\n  Shutting down...")
    for c in covers:
        c.stop()
    print("  Done.")


if __name__ == "__main__":
    main()

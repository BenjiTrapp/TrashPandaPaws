#!/usr/bin/env python3
"""
SMBLoot CLI — Pure-Python SMB2 share browser/downloader.
Zero external dependencies (stdlib only).

Usage:
    python smbloot.py <server> <user> <pass_or_hash> [options] <action> [args]

Actions:
    shares                     List available shares
    ls <share> [path]          List directory
    cat <share> <path>         Read file (text preview)
    get <share> <path> [out]   Download file to local disk
    tree <share> [path]        Recursive directory listing

Options:
    -d, --domain DOMAIN        Domain (default: .)
    -p, --port PORT            SMB port (default: 445)
    --depth N                  Tree recursion depth (default: 3)

Examples:
    python smbloot.py 10.0.0.5 admin P@ssw0rd shares
    python smbloot.py 10.0.0.5 admin P@ssw0rd ls Users
    python smbloot.py 10.0.0.5 admin P@ssw0rd cat SYSVOL domain/Policies/policy.inf
    python smbloot.py 10.0.0.5 admin aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 shares
    python smbloot.py 10.0.0.5 admin P@ssw0rd -d CORP tree C$ Windows\\System32\\drivers
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from beacon import Beacon


def main():
    parser = argparse.ArgumentParser(
        description="SMBLoot — Pure-Python SMB2 share browser (no impacket)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Actions:
  shares                     List available shares
  ls <share> [path]          List directory contents
  cat <share> <path>         Read file as text (max 64KB)
  get <share> <path> [out]   Download file to local disk
  tree <share> [path]        Recursive directory listing

Hash format (pass-the-hash):
  LM:NT   e.g. aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  NT only  e.g. 31d6cfe0d16ae931b73c59d7e0c089c0
""")
    parser.add_argument("server", help="Target SMB server IP or hostname")
    parser.add_argument("username", help="Username for authentication")
    parser.add_argument("credential", help="Password or NT hash (LM:NT or NT)")
    parser.add_argument("-d", "--domain", default=".", help="Domain (default: .)")
    parser.add_argument("-p", "--port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("--depth", type=int, default=3, help="Tree recursion depth (default: 3)")
    parser.add_argument("action", choices=["shares", "ls", "cat", "get", "tree"],
                        help="Action to perform")
    parser.add_argument("args", nargs="*", help="Action arguments (share, path, output)")

    args = parser.parse_args()

    # Build the smbloot args string matching beacon format
    parts = [args.server, args.username, args.credential, args.domain, args.action]
    parts.extend(args.args)
    smbloot_args = " ".join(parts)

    # Create a minimal beacon instance (no C2 connection)
    beacon = Beacon({"c2": {"https": {"enabled": False}, "dns": {"enabled": False}}})

    result = beacon._exec_smbloot(smbloot_args)

    # For 'get' action, decode base64 and write to file
    if args.action == "get" and result.startswith("{"):
        import json
        import base64
        try:
            data = json.loads(result)
            if "error" in data:
                print(f"Error: {data['error']}", file=sys.stderr)
                sys.exit(1)
            filename = data["filename"]
            out_path = args.args[2] if len(args.args) > 2 else filename
            file_data = base64.b64decode(data["data"])
            with open(out_path, "wb") as f:
                f.write(file_data)
            print(f"Downloaded: {out_path} ({data['size']} bytes)")
            sys.exit(0)
        except (json.JSONDecodeError, KeyError):
            pass

    print(result)
    if result.startswith("[") and "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()

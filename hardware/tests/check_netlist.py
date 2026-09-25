#!/usr/bin/env python3
"""
Validate hardware/netlist.yaml before anything is generated from it.

Catches the mistakes that are easy to make by hand and expensive to find later:

  * an endpoint naming a component or pin that does not exist
  * a pin that appears in two nets (a short)
  * a pin that is in no net and not declared no_connect (a float)
  * a power_in pin that is not on any rail
  * a net with fewer than two endpoints (goes nowhere)
  * a no_connect entry that is also wired somewhere

Exit code 0 = clean, 1 = at least one error. Warnings do not fail the run.

Usage:
    python3 check_netlist.py [-v] [path/to/netlist.yaml]
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import yaml

DEFAULT = Path(__file__).resolve().parent.parent / "netlist.yaml"

# Pin types that must be driven by a rail.
POWER_INPUT_TYPES = {"power_in"}
# Pin types that are allowed to sit on exactly one net without complaint.
PASSIVE_TYPES = {"passive", "no_connect"}


def load(path):
    with open(path) as handle:
        return yaml.safe_load(handle)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("netlist", nargs="?", default=str(DEFAULT))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    path = Path(args.netlist)
    if not path.exists():
        print(f"error: {path} not found")
        return 1

    data = load(path)
    components = data.get("components") or {}
    nets = data.get("nets") or {}
    no_connect = data.get("no_connect") or {}
    rails = set(data.get("rails") or {})

    errors, warnings = [], []

    # Build the set of every pin that exists.
    all_pins = set()
    pin_type = {}
    for ref, comp in components.items():
        for number, pin in (comp.get("pins") or {}).items():
            key = f"{ref}.{number}"
            all_pins.add(key)
            pin_type[key] = (pin or {}).get("type", "passive")

    # Walk the nets.
    pin_nets = defaultdict(list)
    for net, endpoints in nets.items():
        if endpoints is None:
            errors.append(f"net {net!r} has no endpoints")
            continue
        if len(endpoints) < 2:
            errors.append(
                f"net {net!r} has only {len(endpoints)} endpoint(s): {endpoints}")
        for endpoint in endpoints:
            if endpoint not in all_pins:
                ref = str(endpoint).split(".")[0]
                if ref not in components:
                    errors.append(f"net {net!r}: component {ref!r} does not exist "
                                  f"(endpoint {endpoint!r})")
                else:
                    errors.append(f"net {net!r}: {endpoint!r} is not a pin of {ref}")
                continue
            pin_nets[endpoint].append(net)

    # Shorts: a pin on more than one net.
    for pin, on in sorted(pin_nets.items()):
        if len(on) > 1:
            errors.append(f"{pin} appears on {len(on)} nets - short: {on}")

    # Floats: a pin on no net and not declared no_connect.
    for pin in sorted(all_pins):
        if pin not in pin_nets and pin not in no_connect:
            errors.append(f"{pin} ({pin_type[pin]}) is on no net and not no_connect")

    # no_connect that is actually connected.
    for pin in sorted(no_connect):
        if pin not in all_pins:
            errors.append(f"no_connect {pin!r} is not a pin of any component")
        elif pin in pin_nets:
            errors.append(f"no_connect {pin!r} is also wired to {pin_nets[pin]}")

    # Power inputs must sit on a declared rail.
    for pin, kind in sorted(pin_type.items()):
        if kind not in POWER_INPUT_TYPES:
            continue
        if pin in no_connect:
            continue
        on = pin_nets.get(pin, [])
        if not on:
            continue  # already reported as a float
        if not any(net in rails for net in on):
            errors.append(f"{pin} is a power_in but its net {on} is not a declared rail")

    # Rails that nothing drives.
    for rail in sorted(rails):
        if rail not in nets:
            warnings.append(f"rail {rail!r} is declared but has no net")

    # Report.
    print(f"Netlist: {path}")
    print(f"  components      {len(components)}")
    print(f"  pins            {len(all_pins)}")
    print(f"  nets            {len(nets)}")
    print(f"  endpoints       {sum(len(v or []) for v in nets.values())}")
    print(f"  no_connect      {len(no_connect)}")

    if args.verbose:
        print("\n  Pins per net:")
        for net, endpoints in nets.items():
            marker = " (rail)" if net in rails else ""
            print(f"    {net:<12} {len(endpoints or []):>3}{marker}")

    print()
    for warning in warnings:
        print(f"  warn  {warning}")
    for error in errors:
        print(f"  FAIL  {error}")

    if errors:
        print(f"\nFAILED - {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1
    print(f"PASSED - netlist is consistent, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

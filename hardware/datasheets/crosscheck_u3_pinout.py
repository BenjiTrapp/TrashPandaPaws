#!/usr/bin/env python3
"""Cross-check U3 (RTL8153B-VB-CG) pin numbers.

Parses the pin-description tables (datasheet section 5, Tables 1-10) out of the
vendored PDFs with pdftotext, builds pin -> symbol maps, and compares them with
(a) each other and (b) the pin list in hardware/netlist.yaml.

Source of truth is the PDFs. netlist.yaml is only the thing being checked.
Exit status is 0 only if every pin 1..41 is found in every PDF, all PDFs agree,
no PDF or netlist pin falls outside 1..41, every netlist name is one of the
datasheet symbols for that pin, and only pins the datasheet's own Table 11
declares shared carry more than one symbol.

Run from the repo root:
    python3 hardware/datasheets/crosscheck_u3_pinout.py             # the check
    python3 hardware/datasheets/crosscheck_u3_pinout.py --selftest  # prove it can fail
"""
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

DS = Path(__file__).parent
PDFS = {
    "rev1.4 lcsc": DS / "RTL8153B-VB-CG_rev1.4_lcsc-datasheet.pdf",
    "rev1.4 oneyac": DS / "RTL8153B-VB-CG_rev1.4_oneyac.pdf",
    "rev1.0 elecfans": DS / "RTL8153B-VB-CG_rev1.0_elecfans.pdf",
}
NETLIST = DS.parent / "netlist.yaml"
EXPECTED = set(range(1, 42))  # 40 pins + exposed pad as pin 41

# symbol-row: SYMBOL TYPE PINLIST, where PINLIST may wrap onto the next line
ROW = re.compile(r"^([A-Z][A-Z0-9_]+)\s+(IO|I|O|P|D)\s+(\d+(?:\s*,\s*\d+)*,?)(?:\s.*)?$")
# symbol-row whose pin list sits entirely on the following line(s)
ROW_BARE = re.compile(r"^([A-Z][A-Z0-9_]+)\s+(IO|I|O|P|D)$")
# a line that is nothing but a (possibly comma-terminated) pin list
PINLIST_LINE = re.compile(r"^\d+(?:\s*,\s*\d+)*,?$")
# MDI rows in the transceiver table: second symbol sits at end of the line or alone
MDI = re.compile(r"\b(MDI[PN][0-3])\s+IO\s+(\d+)\b")


def text(pdf):
    return subprocess.run(
        ["pdftotext", "-raw", str(pdf), "-"], capture_output=True, text=True, check=True
    ).stdout


def section5(t):
    start = t.index("5. Pin Descriptions")
    end = t.index("5.11. Shared Pin Configuration")
    return t[start:end]


def shared_pins(t):
    """Pin numbers the datasheet itself declares shared (section 5.11, Table 11)."""
    start = t.index("Table 11. Shared Pin Modes")
    end = t.index("6. Functional Description", start)
    return {int(n) for n in re.findall(r"(?:^|\s)(\d+)\s+(?:LED\d|-)(?=\s|$)", t[start:end], re.M)}


def continuation(lines, i):
    """Pin numbers on the lines after i, while those lines are pure pin lists.

    Only lines consisting solely of digits and commas count, so a description
    word such as 'U3SSRXN' can never contribute a stray digit.
    """
    nums = []
    j = i + 1
    while j < len(lines) and PINLIST_LINE.match(lines[j]):
        nums += [int(n) for n in re.findall(r"\d+", lines[j])]
        if not lines[j].endswith(","):
            break
        j += 1
    return nums


def parse_text(raw):
    lines = [l.strip() for l in section5(raw).splitlines()]
    pins = defaultdict(set)
    for i, l in enumerate(lines):
        if MDI.search(l):
            for name, num in MDI.findall(l):
                pins[int(num)].add(name)
            continue
        m = ROW.match(l)
        if m:
            name, _, plist = m.groups()
            nums = [int(n) for n in re.findall(r"\d+", plist)]
            if plist.endswith(","):
                nums += continuation(lines, i)
        else:
            m = ROW_BARE.match(l)
            if not m:
                continue
            name = m.group(1)
            nums = continuation(lines, i)
            if not nums:
                print(f"WARNING: symbol row without pin list: {l!r}", file=sys.stderr)
        for n in nums:
            pins[n].add(name)
    return pins


def netlist_pins(path):
    out = {}
    in_u3 = in_pins = False
    for l in path.read_text().splitlines():
        if re.match(r"^  U3:\s*$", l):
            in_u3 = True
            continue
        if in_u3 and re.match(r"^    pins:\s*$", l):
            in_pins = True
            continue
        if in_pins:
            m = re.match(r"^\s+(\d+):\s+\{name:\s*([A-Za-z0-9_]+)", l)
            if m:
                out[int(m.group(1))] = m.group(2)
            elif not l.strip().startswith("#") and not re.match(r"^\s+\d+:", l):
                break
    return out


def check(maps, nl, shared, quiet=False):
    """Return (rc, mismatches). rc is 0 only if everything agrees.

    shared: label -> set of pins Table 11 declares shared. A pin may carry more
    than one symbol only if every PDF lists it there; anywhere else a second
    symbol means a mis-assigned row and fails the check.
    """
    say = (lambda *a: None) if quiet else print
    bad = []
    allowed_multi = set.intersection(*shared.values())
    say("pin | " + " | ".join(maps) + " | netlist.yaml | verdict")
    for p in sorted(EXPECTED):
        cols = [",".join(sorted(m.get(p, ()))) or "-" for m in maps.values()]
        nlname = nl.get(p, "-")
        names = set().union(*[m.get(p, set()) for m in maps.values()])
        agree = len(set(cols)) == 1 and cols[0] != "-"
        # shared pins are listed under several symbols in section 5; the netlist
        # records only the function this design uses, which must be one of them
        ok = agree and nlname in names and (len(names) == 1 or p in allowed_multi)
        if not ok:
            bad.append(p)
        say(f"{p:>3} | " + " | ".join(cols) + f" | {nlname} | {'OK' if ok else 'MISMATCH'}")
    for label, m in maps.items():
        extra = sorted(set(m) - EXPECTED)
        if extra:
            bad.append(f"{label}: pins outside 1..41: {extra}")
    extra = sorted(set(nl) - EXPECTED)
    if extra:
        bad.append(f"netlist.yaml: pins outside 1..41: {extra}")
    allpins = sorted(set().union(*[set(m) for m in maps.values()]))
    say("pins found in PDFs:", allpins)
    say("shared pins per Table 11:", sorted(allowed_multi))
    say("result:", "ALL 41 PINS AGREE" if not bad else f"FAIL {bad}")
    return (1 if bad else 0), bad


def selftest(raws, nl):
    """Mutate the real inputs and require the check to fail each time."""
    def run(texts, netlist):
        return check({k: parse_text(v) for k, v in texts.items()}, netlist,
                     {k: shared_pins(v) for k, v in texts.items()}, quiet=True)

    rc, bad = run(raws, nl)
    assert rc == 0, f"baseline must pass, got {bad}"
    first = next(iter(raws))
    cases = []

    # 1. one PDF says REGOUT is pin 27 instead of 28
    t = dict(raws)
    t[first] = t[first].replace("REGOUT O 28", "REGOUT O 27", 1)
    cases.append(("one PDF moves REGOUT 28->27", t, nl, 28))

    # 2. all PDFs drop the exposed-pad row (common-mode loss of a pin)
    t = {k: v.replace("GND P 41", "", 1) for k, v in raws.items()}
    cases.append(("all PDFs lose pin 41", t, nl, 41))

    # 3. all PDFs consistently shift RSET 38->39: inter-PDF agreement holds,
    #    so only the netlist comparison can catch it
    t = {k: v.replace("RSET I 38", "RSET I 39", 1) for k, v in raws.items()}
    cases.append(("all PDFs shift RSET 38->39", t, nl, 38))

    # 4. netlist swaps two supply pins
    n = dict(nl)
    n[21], n[22] = n[22], n[21]
    cases.append(("netlist swaps VDD5/DVDD10_UPS", raws, n, 21))

    # 5. wrapped AVDD33 list loses its continuation line
    t = {k: re.sub(r"(AVDD33 P\s*\n\s*11, 20, 39,)\s*\n\s*40", r"\1\nX", v, count=1)
         for k, v in raws.items()}
    cases.append(("AVDD33 wrap loses pin 40", t, nl, 40))

    # 6. netlist invents a pin 42
    n = dict(nl)
    n[42] = "GND"
    cases.append(("netlist adds pin 42", raws, n, "netlist.yaml"))

    # 7. all PDFs gain a stray row putting AVDD33 on pin 21 as well: VDD5 is
    #    still there and matches the netlist, so only the shared-pin rule catches it
    t = {k: v.replace("VDD5 P 21", "VDD5 P 21\nAVDD33 P 21", 1) for k, v in raws.items()}
    cases.append(("all PDFs add AVDD33 to pin 21", t, nl, 21))

    failures = 0
    for label, texts, netlist, expect in cases:
        changed = texts != raws or netlist != nl
        rc, bad = run(texts, netlist)
        hit = any(expect == b or (isinstance(b, str) and str(expect) in b) for b in bad)
        status = "caught" if (changed and rc == 1 and hit) else "MISSED"
        if status == "MISSED":
            failures += 1
        print(f"selftest: {label:<34} mutation applied={changed} -> {status} {bad}")
    print("selftest:", "PASS" if not failures else f"FAIL ({failures} mutation(s) not caught)")
    return 1 if failures else 0


def main():
    raws = {k: text(v) for k, v in PDFS.items()}
    nl = netlist_pins(NETLIST)
    if "--selftest" in sys.argv[1:]:
        return selftest(raws, nl)
    rc, _ = check({k: parse_text(v) for k, v in raws.items()}, nl,
                  {k: shared_pins(v) for k, v in raws.items()})
    return rc


if __name__ == "__main__":
    sys.exit(main())

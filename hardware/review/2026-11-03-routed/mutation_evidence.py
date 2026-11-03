#!/usr/bin/env python3
"""
Show, with numbers, that the two ruling-BJ checks in tests/check_fab_release.py
fail on the defects they exist for. Plants each defect on a scratch copy of the
committed board and prints what the checks say. The committed board is never
written.

    python3 hardware/review/2026-11-03-routed/mutation_evidence.py
"""

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tests"))
import check_fab_release as c  # noqa: E402


def share(summary, net):
    r = summary[net]
    return (f"{net:15s} {100 * r['window'] / r['length']:3.0f} % in the window, "
            f"{100 * r['at_gap'] / r['length']:3.0f} % at the designed gap, "
            f"floor {100 * c.coupled_floor(net):.0f} %, in no region {r['unregioned']:.2f} mm")


def show_coupling(tmp, title, net, *step):
    print(f"\n== {title} ==")
    probe = c.run_probe(c.mutate_board(tmp, *step), "--coupling")
    print(" ", share(c.coupling_summary(probe), net))
    for m in c.pair_coupling_problems(probe):
        if m.startswith(net + ":"):
            print("   ", m)


HISTORY = (("732475b", "task 9 as reviewed: the board of review 1 (TX 0 % coupled, RX 28 %, USB 2.0 over D+'s antipad)"),
           ("584ece4", "after fix round 1 (TX coupled, RX still 28 %)"),
           ("b13cff9", "after fix round 2 (ruling BK: RX 56 / 54 %)"))


def show_history(tmp):
    """The checks on the boards that actually carried the defects, from git."""
    for rev, what in HISTORY:
        board = Path(tmp) / f"{rev}.kicad_pcb"
        board.write_text(subprocess.run(["git", "show", f"{rev}:hardware/kicad/raccoon-tap.kicad_pcb"],
                                        cwd=HERE, capture_output=True, text=True, check=True).stdout)
        probe = c.run_probe(board, "--coupling", "--in1")
        coupling, in1 = c.pair_coupling_problems(probe), c.in1_continuity_problems(probe)
        summary = c.coupling_summary(probe)
        print(f"\n== {rev}: {what} ==")
        print(f"  coupling problems {len(coupling)}, In1 problems {len(in1)}; share of each SuperSpeed net inside "
              f"the impedance window: " + ", ".join(f"{n[5:]} {100 * r['window'] / r['length']:.0f} %"
                                                    for n, r in summary.items() if n.startswith("USB3")))
        for m in coupling[:4] + in1[:2]:
            print("   ", m)


def main():
    committed = c.committed_probe("--coupling")
    print("== committed board, coupling ==")
    base = c.coupling_summary(committed)
    for net in c.BOARD_PAIR_NETS:
        print(" ", share(base, net))
    print("  problems:", c.pair_coupling_problems(committed))
    print("== committed board, In1 ==")
    print("  problems:", c.in1_continuity_problems(c.committed_probe("--in1")))

    with tempfile.TemporaryDirectory() as tmp:
        show_history(tmp)
        show_coupling(tmp, "defect: RX_N 0.45 mm further from RX_P along x 7.5 to 24.5 "
                           "(task 9 review 1 found RX 28 % coupled)",
                      "USB3_RX_N", "shift", "USB3_RX_N", 0, 0.45, 7.5, 24.5)
        show_coupling(tmp, "defect: TX_P 0.30 mm further from TX_N along its whole run",
                      "USB3_TX_P", "shift", "USB3_TX_P", -0.3, 0, 20.0, 30.0)
        show_coupling(tmp, "defect: MDI1_N 0.30 mm further from MDI1_P along its whole run",
                      "MDI1_N", "shift", "MDI1_N", 0, 0.3, 0.0, 60.0)

        print("\n== defect: a hole in In1 under each pair (0.8 x 0.5 mm, at the middle of its F.Cu run) ==")
        source = c.PCB
        for i, net in enumerate(c.BOARD_PAIR_NETS):
            x, y = c._mid_sample(committed, net)
            target = Path(tmp) / f"void{i}.kicad_pcb"
            subprocess.run([str(c.kicad_python()), str(c.BOARD_MUTATE), str(source), str(target), "void-in1",
                            str(round(x - 0.4, 2)), str(round(y - 0.25, 2)), str(round(x + 0.4, 2)),
                            str(round(y + 0.25, 2))], check=True, capture_output=True)
            source = target
        problems = c.in1_continuity_problems(c.run_probe(source, "--in1"))
        for net in c.BOARD_PAIR_NETS:
            hits = [m for m in problems if m.startswith(net + ":") and "without In1 ground" in m]
            print(f"  {net:15s} {'FOUND: ' + hits[0] if hits else 'NOT FOUND'}")

        print("\n== defect: a +3V3 via 0.52 mm beside RX_P (touches nothing; its antipad opens In1) ==")
        x, y = next(s[:2] for s in committed["coupling"]["USB3_RX_P"] if abs(s[0] - 9.5) < 0.03)
        board = c.mutate_board(tmp, "via", "+3V3", round(x, 2), round(y + 0.52, 2), 0.6, 0.3)
        problems = c.in1_continuity_problems(c.run_probe(board, "--in1"))
        print("  ", [m for m in problems if m.startswith("USB3_RX")][:2])

        print("\n== defect: the north AR flank via removed ==")
        board = c.mutate_board(tmp, "remove-via", 19.1, 18.49)
        print("  ", [m for m in c.in1_continuity_problems(c.run_probe(board, "--in1")) if "flank" in m])


if __name__ == "__main__":
    main()

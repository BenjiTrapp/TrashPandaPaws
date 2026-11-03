#!/usr/bin/env python3
"""
Export the PCBWay fabrication set of the routed raccoon-tap board (task 11).

    python3 hardware/tools/export_fab.py [--out hardware/fab/gerber] [--cpl hardware/fab/raccoon-tap-cpl.csv]

Writes, into one folder:

  * gerbers for F.Cu, In1.Cu (GND), In2.Cu (Power), B.Cu, both masks, both
    silkscreens and Edge.Cuts, and the Excellon drill files (PTH and NPTH, with
    the PDF drill map), all by `kicad-cli`;
  * F.Paste, with paste openings for U3 and Y1 only. The board's own F.Paste has
    an opening on every top pad; PCBWay places only U3 and Y1 and the operator
    solders the rest, so a stencil cut from the full layer would put paste on
    pads that are then reflowed into lumps before the hand work. The layer is
    plotted from a scratch copy of the board whose other pads have no paste
    (the board file itself is never written);
  * the DRC report of the board (`kicad-cli pcb drc --severity-all
    --refill-zones`), which has to be clean or nothing is written;
  * KiCad's job file, `raccoon-tap-job.gbrjob`, amended (`amend_job_file`):
    the board file has no stackup section, so KiCad writes its default stackup
    (0.48 mm of FR4 between each pair of copper layers), finish "None" and its
    netclass clearances as "DesignRules". All three contradict the order. The
    stackup is replaced by PCBWay's entry 1 as `fab/stackup-note.md` gives it,
    the finish by ENIG (ruling CA), and the DesignRules block is removed: the
    board's real minima (0.15 mm track, 0.15 mm gap between U3's pads, 0.17 mm
    USB3 pair gap) are stated in `fab/ORDERING.md`, not in KiCad's netclass
    figures. The paste layer, plotted separately, is added to its file list;
  * `release-manifest.json`: SHA-256 of the board, its rules file and its
    project file, of every file in the set, and the KiCad version. The freshness
    check in tests/check_fab_release.py reads it.

The component placement list (CPL) for the partial assembly is written from the
same board. Which parts are machine-assembled (U3 and Y1, rulings Y and AC) is
read from netlist.yaml, the components that carry an `assembly:` mapping, and
nowhere else: the paste layer, the manifest, the CPL and, through tools/gen_bom.py,
the assembly BOM beside it all take their references from there.

The set is built in a temporary folder and replaces the old one only when every
step succeeded. Nothing is uploaded, ordered or paid for.

Environment: KIPY (KiCad's Python, needs pcbnew; default is the macOS bundle),
KICAD_CLI (default: the one on PATH, else the app bundle).
"""

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARDWARE = Path(__file__).resolve().parent.parent
PCB = HARDWARE / "kicad" / "raccoon-tap.kicad_pcb"
DRU = HARDWARE / "kicad" / "raccoon-tap.kicad_dru"
PRO = HARDWARE / "kicad" / "raccoon-tap.kicad_pro"
OUT = HARDWARE / "fab" / "gerber"
CPL = HARDWARE / "fab" / "raccoon-tap-cpl.csv"
ASSEMBLY_BOM = HARDWARE / "fab" / "raccoon-tap-assembly-bom.csv"
NETLIST = HARDWARE / "netlist.yaml"

KIPY = Path(os.environ.get("KIPY") or "/Applications/KiCad/KiCad.app/Contents/"
            "Frameworks/Python.framework/Versions/3.9/bin/python3")
KICAD_CLI = os.environ.get("KICAD_CLI") or shutil.which("kicad-cli") or \
    "/Applications/KiCad/KiCad.app/Contents/MacOS/kicad-cli"

MANIFEST = "release-manifest.json"
DRC_REPORT = "raccoon-tap-drc.rpt"
GERBER_LAYERS = "F.Cu,In1.Cu,In2.Cu,B.Cu,F.Silkscreen,B.Silkscreen,F.Mask,B.Mask,Edge.Cuts"
JOB_FILE = "raccoon-tap-job.gbrjob"
PASTE_FILE = "raccoon-tap-F_Paste.gtp"
FINISH = "ENIG"                                  # ruling CA

# PCBWay "PCB standard stackup", 4 layers, 1.6MM, entry 1, as the table in
# hardware/fab/stackup-note.md ("## Stackup") gives it; tests/check_fab_release.py
# reads that table and compares (JobFileAgreesWithTheStackupNote). Thicknesses are
# after lamination where the note has that column filled, else nominal (the core).
_PREPREG = {"Type": "Dielectric", "Thickness": 0.1855, "Material": "FR4",
            "DielectricConstant": 4.74,
            "Notes": "prepreg 7628 RC46%, 0.1855 mm after lamination (0.1960 nominal); "
                     "PCBWay standard stackup 4 layers 1.6MM entry 1, see stackup-note.md"}
_CORE = {"Type": "Dielectric", "Thickness": 1.03, "Material": "FR4", "DielectricConstant": 4.6,
         "Notes": "core 1.0300 mm; PCBWay standard stackup 4 layers 1.6MM entry 1, see stackup-note.md"}
_OUTER_CU = "outer base copper 0.5 oz plated to 1 oz finished"
_INNER_CU = "inner copper 1 oz"


def _job_stackup():
    mask = "solder mask: PCBWay's, the number of passes is Question 1 of ORDERING.md"
    return [
        {"Type": "Legend", "Name": "Top Silk Screen"},
        {"Type": "SolderPaste", "Name": "Top Solder Paste"},
        {"Type": "SolderMask", "Name": "Top Solder Mask", "Notes": mask},
        {"Type": "Copper", "Thickness": 0.035, "Name": "F.Cu", "Notes": _OUTER_CU},
        dict(_PREPREG, Name="F.Cu/GND"),
        {"Type": "Copper", "Thickness": 0.035, "Name": "GND", "Notes": _INNER_CU},
        dict(_CORE, Name="GND/Power"),
        {"Type": "Copper", "Thickness": 0.035, "Name": "Power", "Notes": _INNER_CU},
        dict(_PREPREG, Name="Power/B.Cu"),
        {"Type": "Copper", "Thickness": 0.035, "Name": "B.Cu", "Notes": _OUTER_CU},
        {"Type": "SolderMask", "Name": "Bottom Solder Mask", "Notes": mask},
        {"Type": "SolderPaste", "Name": "Bottom Solder Paste"},
        {"Type": "Legend", "Name": "Bottom Silk Screen"},
    ]


def amend_job_file(path, paste_gerber):
    """Correct KiCad's job file in place (see the module docstring): stackup,
    finish, no netclass DesignRules, and the separately plotted paste layer in
    the file list, with the function and polarity its own X2 header declares."""
    path = Path(path)
    job = json.loads(path.read_text())
    if [l.get("Thickness") for l in job["MaterialStackup"] if l["Type"] == "Dielectric"] != [0.48] * 3:
        raise ExportFailed(f"{path.name}: KiCad's stackup is not the expected default; "
                           "the board may have gained a stackup section, check it before overriding")
    job["GeneralSpecs"]["Finish"] = FINISH
    job.pop("DesignRules", None)
    job["MaterialStackup"] = _job_stackup()
    header = Path(paste_gerber).read_text()
    function = re.search(r"%TF\.FileFunction,([^*]+)\*%", header).group(1)
    polarity = re.search(r"%TF\.FilePolarity,([^*]+)\*%", header).group(1)
    files = [f for f in job["FilesAttributes"] if f["Path"] != Path(paste_gerber).name]
    files.append({"Path": Path(paste_gerber).name, "FileFunction": function, "FilePolarity": polarity})
    job["FilesAttributes"] = files
    path.write_text(json.dumps(job, indent=2) + "\n")


def assembled_refs(netlist_path=None):
    """The references PCBWay places: the components of netlist.yaml that carry an
    `assembly:` mapping (rulings Y and AC make them U3 and Y1; the netlist, not
    this file, says so). The single source for the CPL, the paste layer, the
    manifest and, through tools/gen_bom.py, the assembly BOM. Imported late:
    this file also runs under KiCad's Python, which has no PyYAML."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import gen_bom
    import yaml
    netlist_path = netlist_path or NETLIST
    refs = tuple(gen_bom.assembly_refs(yaml.safe_load(Path(netlist_path).read_text())))
    if not refs:
        raise ExportFailed(f"{netlist_path} marks no component with `assembly:`")
    return refs


class ExportFailed(RuntimeError):
    pass


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(cmd, **kw):
    result = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    if result.returncode != 0:
        raise ExportFailed(f"{' '.join(str(c) for c in cmd)}\n{result.stdout}{result.stderr}")
    return result


def kicad_version():
    return run([KICAD_CLI, "version"]).stdout.strip()


def paste_board(src, dst, keep_refs):
    """Run under KiCad's Python: a copy of `src` in which no pad of any footprint
    outside `keep_refs` has a paste layer."""
    import pcbnew
    board = pcbnew.LoadBoard(str(src))
    kept = set()
    for fp in board.GetFootprints():
        if fp.GetReference() in keep_refs:
            kept.add(fp.GetReference())
            continue
        for pad in fp.Pads():
            layers = pad.GetLayerSet()
            layers.RemoveLayer(pcbnew.F_Paste)
            layers.RemoveLayer(pcbnew.B_Paste)
            pad.SetLayerSet(layers)
    if kept != set(keep_refs):
        raise SystemExit(f"footprints not found on the board: {sorted(set(keep_refs) - kept)}")
    board.Save(str(dst))


def export_drc(board, report):
    run([KICAD_CLI, "pcb", "drc", "--severity-all", "--refill-zones", "--output", report, board])


def export_set(out_dir, drc_problems, board=PCB, dru=DRU, pro=PRO, refs=None):
    """Build the set in `out_dir` (which must be empty or new). Returns the
    manifest dictionary. `drc_problems(report_text, board_name)` is
    check_fab_release.drc_report_problems; any problem it names stops the
    export before a gerber is written. `refs` are the parts with paste openings
    (default: those the netlist marks, `assembled_refs()`). Raises ExportFailed
    when a step fails."""
    refs = tuple(refs) if refs is not None else assembled_refs()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs = {"board": sha256_of(board), "rules": sha256_of(dru), "project": sha256_of(pro)}

    report = out_dir / DRC_REPORT
    export_drc(board, report)
    problems = drc_problems(report.read_text(), Path(board).name)
    if problems:
        raise ExportFailed("the board does not pass DRC, no gerbers were written:\n  "
                           + "\n  ".join(problems))

    run([KICAD_CLI, "pcb", "export", "gerbers", "--check-zones", "--layers", GERBER_LAYERS,
         "--output", out_dir, board])
    run([KICAD_CLI, "pcb", "export", "drill", "--excellon-separate-th", "--generate-map",
         "--map-format", "pdf", "--output", str(out_dir) + "/", board])

    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        shutil.copy(pro, scratch / "raccoon-tap.kicad_pro")
        shutil.copy(dru, scratch / "raccoon-tap.kicad_dru")
        run([KIPY, __file__, "--paste-board", board, scratch / "raccoon-tap.kicad_pcb",
             *refs])
        run([KICAD_CLI, "pcb", "export", "gerbers", "--layers", "F.Paste",
             "--output", scratch, scratch / "raccoon-tap.kicad_pcb"])
        shutil.copy(scratch / PASTE_FILE, out_dir / PASTE_FILE)
    amend_job_file(out_dir / JOB_FILE, out_dir / PASTE_FILE)

    if {k: sha256_of(p) for k, p in (("board", board), ("rules", dru), ("project", pro))} != inputs:
        raise ExportFailed("the board, rules or project file changed during the export")

    files = {p.name: sha256_of(p) for p in sorted(out_dir.iterdir())
             if p.is_file() and p.name != MANIFEST}
    manifest = {
        "about": "Written by hardware/tools/export_fab.py. The gerber set binds to the "
                 "SHA-256 of the board, rules and project files below; "
                 "tests/check_fab_release.py (check_gerber_freshness) compares them.",
        "kicad": kicad_version(),
        "inputs": inputs,
        "paste_openings_only_for": list(refs),
        "files": files,
    }
    (out_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def write_cpl(path, board=PCB, refs=None):
    """CPL for `refs` in the gerber coordinate system: KiCad's own position
    export (Y up, as in the gerbers, origin at the page origin because the board
    has no drill/place origin), renamed to the column heads PCBWay's sample
    uses. Rotation is KiCad's footprint orientation; whether it is the right one
    is checked against the pin-1 marking in tests/check_fab_release.py. `refs`
    default to the parts the netlist marks for assembly (`assembled_refs()`)."""
    refs = tuple(refs) if refs is not None else assembled_refs()
    with tempfile.TemporaryDirectory() as scratch:
        pos = Path(scratch) / "pos.csv"
        run([KICAD_CLI, "pcb", "export", "pos", "--format", "csv", "--units", "mm",
             "--side", "both", "--smd-only", "--output", pos, board])
        rows = {r["Ref"]: r for r in csv.DictReader(pos.read_text().splitlines())}
    missing = [r for r in refs if r not in rows]
    if missing:
        raise ExportFailed(f"not in the position export: {missing}")
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["Designator", "Val", "Package", "Mid X", "Mid Y", "Rotation", "Layer"])
        for ref in refs:
            r = rows[ref]
            w.writerow([ref, r["Val"], r["Package"], f"{float(r['PosX']):.4f}",
                        f"{float(r['PosY']):.4f}", f"{float(r['Rot']):.0f}",
                        r["Side"].capitalize()])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--cpl", default=str(CPL))
    ap.add_argument("--assembly-bom", default=str(ASSEMBLY_BOM))
    ap.add_argument("--paste-board", nargs="+", metavar="ARG",
                    help="internal: SRC DST REF... (run under KiCad's Python)")
    args = ap.parse_args(argv)
    if args.paste_board:
        src, dst, *refs = args.paste_board
        paste_board(src, dst, refs)
        return 0
    sys.path.insert(0, str(HARDWARE / "tests"))
    import check_fab_release as chk

    out = Path(args.out)
    with tempfile.TemporaryDirectory() as build:
        build = Path(build) / "gerber"
        try:
            refs = assembled_refs()       # parsed once; the three outputs below share it
            manifest = export_set(build, chk.drc_report_problems, refs=refs)
            cpl = Path(build).parent / "cpl.csv"
            write_cpl(cpl, refs=refs)
            import gen_bom
            import yaml
            bom = Path(build).parent / "assembly-bom.csv"
            placed = [r["Reference Designator"] for r in gen_bom.write_assembly_bom(
                yaml.safe_load(NETLIST.read_text()), bom)]
            # Both lists come from netlist.yaml's `assembly:` marks, so this can fire only if
            # gen_bom.build_assembly_rows and gen_bom.assembly_refs ever diverge in code; it is a
            # cheap tripwire for that, not an independent check of the BOM against the CPL.
            if tuple(placed) != refs:
                raise ExportFailed(f"assembly BOM {placed} and CPL {list(refs)} disagree")
        except (ExportFailed, ValueError) as e:
            print(f"export_fab: {e}", file=sys.stderr)
            return 2
        if out.exists():
            shutil.rmtree(out)
        shutil.copytree(build, out)
        shutil.copy(cpl, args.cpl)
        shutil.copy(bom, args.assembly_bom)
    print(f"wrote {len(manifest['files']) + 1} files to {out}, {args.cpl} and {args.assembly_bom}")
    print(f"board SHA-256 {manifest['inputs']['board']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

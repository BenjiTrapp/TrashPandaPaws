#!/usr/bin/env python3
"""Shoot a sequence of frames from one browser session, for a GIF.

tools/capture_gui.py takes one picture per run, launching and discarding a
browser each time. A tour needs twenty-odd screens in one consistent
session -- same fleet, same scroll positions, the same beacon still
checked in -- and an agent campaign needs frames taken *while* it runs,
which a fresh browser per shot cannot do at all.

So this keeps one Chrome open and walks a storyboard: a list of steps, each
one some JavaScript to run against the GUI, something to wait for, and how
long that screen should be held in the finished GIF. It writes numbered
PNGs and the manifest tools/make_gif.py reads.

    python3 tools/capture_sequence.py --url http://127.0.0.1:18500/ \
        --storyboard tools/storyboards/c2_tour.json --out-dir /tmp/tour

Captions are injected into the page and rasterised by the browser with
everything else, rather than drawn onto the PNG afterwards -- which would
need a font file and would come out at a different weight from the UI
around it.

Needs nothing that is not already here: Chrome is on the machine and
aiohttp is the agent's own dependency. The GUI authenticates itself.
"""

import argparse
import asyncio
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import NamedTuple, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.capture_gui import Cdp, find_chrome, free_port, shoot, wait_for
# Re-exported: both this tool and tools/scripted_model.py substitute the
# same placeholders, so there is one implementation of it.
from tools.placeholders import fill

CAPTION_ID = "capture-caption"

# The GUI's shell is height:100vh, so a fixed bar at the bottom covers the
# command input -- part of the very feature the terminal frames exist to
# show. The shell is shortened by the caption's height instead, which
# costs the figures 52 of 900 pixels and hides nothing.
SHELL_SELECTOR = "#app"
CAPTION_HEIGHT = 52

_FIELDS = {"hold", "js", "caption", "wait", "settle", "note", "shoot",
           "timeout"}

# Long enough for the GUI's own fetches to land. It fills itself from
# several requests, and a step that shoots too early catches a spinner --
# which is why most steps also name something to wait for.
DEFAULT_SETTLE = 0.9

# A campaign takes about a minute to reach its exploitation phase, and the
# 20s this used to inherit expired before the frame meant to show the knock
# card -- so the capture carried on and shot the stream again under a
# caption claiming a card that was not on screen. Per-step, because most
# steps should fail fast when a selector is wrong.
DEFAULT_TIMEOUT = 30.0


class Step(NamedTuple):
    hold: float
    js: Optional[str]
    caption: Optional[str]
    wait: Optional[str]
    settle: float
    timeout: float
    # A step that acts on the page without being photographed: dismissing
    # the connect toasts, widening a panel, closing what the last step
    # opened. The first version had no such thing, so the toast-dismissing
    # step became frame 0 of the tour -- a tenth of a second of
    # undismissed toasts at the very start.
    shoot: bool


# Delimited, not guessed. The first version matched any run of capitals,
# so captions mentioning SMB, LDAP, NTLM and MSSQL were read as unfilled
# placeholders and the capture refused to start before taking a frame.
def parse(storyboard):
    """Validate a storyboard strictly and return its steps.

    Strictly because it is written by hand and read once, hours before
    anyone looks at the result: a misspelled key that is quietly ignored
    costs a whole capture run to discover, and a wrong hold time is
    invisible until someone sits through the finished GIF.
    """
    if not storyboard:
        raise ValueError("the storyboard has no steps")
    steps = []
    for index, raw in enumerate(storyboard, 1):
        unknown = sorted(set(raw) - _FIELDS)
        if unknown:
            raise ValueError("step %d has unknown key(s): %s"
                             % (index, ", ".join(unknown)))
        if "hold" not in raw:
            raise ValueError("step %d has no hold time" % index)
        hold = float(raw["hold"])
        if hold <= 0:
            raise ValueError("step %d has a hold of %r; a frame has to be "
                             "on screen for some length of time"
                             % (index, raw["hold"]))
        steps.append(Step(hold=hold, js=raw.get("js"),
                          caption=raw.get("caption"), wait=raw.get("wait"),
                          settle=float(raw.get("settle", DEFAULT_SETTLE)),
                          timeout=float(raw.get("timeout", DEFAULT_TIMEOUT)),
                          shoot=bool(raw.get("shoot", True))))
    return steps


def write_manifest(directory, names, steps):
    """The text file make_gif reads: one `name.png <seconds>` per line."""
    if len(names) != len(steps):
        raise ValueError("%d frames for %d steps" % (len(names), len(steps)))
    for name in names:
        if " " in name:
            # The manifest splits on the last space, so a name containing
            # one parses as a different file with a nonsense hold.
            raise ValueError("frame name contains a space: %r" % name)
    path = pathlib.Path(directory) / "frames.txt"
    lines = []
    for name, step in zip(names, steps):
        if step.caption:
            lines.append("# %s" % step.caption)
        lines.append("%s %s" % (name, step.hold))
    path.write_text("\n".join(lines) + "\n")
    return path


def caption_js(text):
    """JS that sets or clears the caption element.

    One stable id, because set and clear have to agree on it: without
    that, captions pile up and every later frame carries all the earlier
    ones.
    """
    shell = json.dumps(SHELL_SELECTOR)
    if text is None:
        return ("(() => { const e = document.getElementById(%s);"
                " if (e) e.remove();"
                " const s = document.querySelector(%s);"
                " if (s) s.style.height = '100vh';"
                " return true; })()"
                % (json.dumps(CAPTION_ID), shell))
    return (
        "(() => {"
        " const s = document.querySelector(%(shell)s);"
        " if (s) s.style.height = 'calc(100vh - %(h)dpx)';"
        " let e = document.getElementById(%(id)s);"
        " if (!e) { e = document.createElement('div'); e.id = %(id)s;"
        "   e.style.cssText = 'position:fixed;left:0;right:0;bottom:0;"
        "z-index:99999;height:%(h)dpx;box-sizing:border-box;"
        "display:flex;align-items:center;padding:0 22px;"
        "font:600 19px/1.3 ui-sans-serif,-apple-system,Segoe UI,sans-serif;"
        "color:#f5f3f0;background:#0b0d11;"
        "border-top:2px solid #c0392b;letter-spacing:0.01em';"
        "   document.body.appendChild(e); }"
        " e.textContent = %(text)s; return true; })()"
        % {"id": json.dumps(CAPTION_ID), "text": json.dumps(text),
           "shell": shell, "h": CAPTION_HEIGHT})


_WRAP_PREFIX = "(function(){ "


def step_js(snippet):
    """A step's JavaScript, in a scope of its own.

    Every step is evaluated in the page's global scope, where a top-level
    `const` creates a binding that outlives the evaluation -- so two steps
    each declaring `const h4` threw "already declared" on the second,
    reported only as "Uncaught", four frames into a run that had already
    launched a campaign. Wrapping makes a step a self-contained snippet,
    which is what a storyboard reads like.
    """
    if snippet.startswith(_WRAP_PREFIX):
        return snippet
    return _WRAP_PREFIX + snippet + " })()"


async def _run_step(cdp, step):
    if step.js:
        await cdp.eval(step_js(step.js))
    if step.wait:
        expression = step.wait
        if not expression.strip().startswith(("document", "window", "!", "(")):
            expression = "document.querySelector(%s)" % json.dumps(expression)
        await wait_for(cdp, expression, what=step.wait,
                       timeout=step.timeout)
    await asyncio.sleep(step.settle)
    await cdp.eval(caption_js(step.caption))
    # A beat after the caption so its own paint has landed.
    await asyncio.sleep(0.15)


async def run(args):
    import aiohttp

    values = dict(pair.split("=", 1) for pair in args.set or [])
    text = fill(pathlib.Path(args.storyboard).read_text(), values)
    steps = parse(json.loads(text))
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    chrome = find_chrome(args.chrome)
    port = free_port()
    profile = tempfile.mkdtemp(prefix="capture-seq-")
    proc = subprocess.Popen(
        [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--no-first-run", "--no-default-browser-check",
         "--disable-extensions", "--mute-audio",
         "--user-data-dir=" + profile,
         "--force-device-scale-factor=%d" % args.scale,
         "--window-size=%d,%d" % (args.width, args.height),
         "--remote-debugging-port=%d" % port, "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    names = []
    try:
        async with aiohttp.ClientSession() as session:
            target = await _first_target(session, port)
            async with session.ws_connect(target, max_msg_size=0) as ws:
                cdp = Cdp(session, ws)
                await cdp.call("Page.enable")
                await cdp.call("Runtime.enable")
                await cdp.call("Page.navigate", url=args.url)
                await wait_for(cdp, "document.readyState === 'complete'",
                               what="the page to load")
                if args.ready:
                    await wait_for(cdp, args.ready, what=args.ready)
                for step in steps:
                    await _run_step(cdp, step)
                    if not step.shoot:
                        print("  (setup)   %s" % (step.js or "")[:60])
                        sys.stdout.flush()
                        continue
                    name = "%04d.png" % len(names)
                    await shoot(cdp, str(out_dir / name), scale=args.scale)
                    names.append(name)
                    print("  %s  %-44s %.1fs"
                          % (name, (step.caption or "")[:44], step.hold))
                    sys.stdout.flush()
    finally:
        proc.terminate()
        with contextlib_suppress():
            proc.wait(timeout=5)

    shot = [s for s in steps if s.shoot]
    manifest = write_manifest(out_dir, names, shot)
    print("%d frames, %.1f s total -> %s"
          % (len(names), sum(s.hold for s in shot), manifest))
    return 0


class contextlib_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


async def _first_target(session, port):
    for _ in range(100):
        try:
            async with session.get("http://127.0.0.1:%d/json/list" % port) as r:
                targets = await r.json()
            for target in targets:
                if target.get("type") == "page":
                    return target["webSocketDebuggerUrl"]
        except Exception:
            pass
        await asyncio.sleep(0.1)
    raise SystemExit("Chrome did not expose a page target")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True)
    parser.add_argument("--storyboard", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=900)
    parser.add_argument("--scale", type=int, default=2)
    parser.add_argument("--ready", help="JS that must be true before step 1")
    parser.add_argument("--chrome")
    parser.add_argument("--set", action="append", metavar="NAME=VALUE",
                        help="fill a placeholder in the storyboard")
    args = parser.parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())

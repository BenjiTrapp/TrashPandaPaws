#!/usr/bin/env python3
"""Capture the C2 operator GUI at documentation quality.

Why this exists rather than a screen grab: a screen grab is whatever the
display happens to be, and the result was 1440x900 JPEG that went soft the
moment anything was cropped out of it. This drives headless Chrome over the
DevTools Protocol, so the page is laid out at a chosen size and rendered at
a chosen pixel density -- real pixels, not an upscale -- and written as PNG.

    python3 tools/capture_gui.py --url http://127.0.0.1:18443/ \
        --out docs/screenshots/30_agent_form.png \
        --click .agent-card --click button.ai-btn --clip "#ai-form"

Steps run in the order given on the command line. `--clip` takes the final
shot of one element instead of the viewport, which is how a panel is
captured legibly without cropping a larger image.

Needs nothing that is not already here: Chrome is on the machine, and
aiohttp is the agent's own dependency. The GUI authenticates itself --
the server injects the operator token into the page it serves -- so there
is no credential to pass in and none to leak into a file.
"""

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)


def find_chrome(explicit=None) -> str:
    for candidate in filter(None, (explicit,) + CHROME_CANDIDATES):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("google-chrome") or shutil.which("chromium")
    if found:
        return found
    raise SystemExit("no Chrome or Chromium found; pass --chrome <path>")


def free_port() -> int:
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Cdp:
    """The few DevTools calls this needs, over one websocket."""

    def __init__(self, session, ws):
        self._session = session
        self._ws = ws
        self._id = 0

    async def call(self, method, **params):
        self._id += 1
        want = self._id
        await self._ws.send_json({"id": want, "method": method,
                                  "params": params})
        while True:
            message = await self._ws.receive_json()
            if message.get("id") == want:
                if "error" in message:
                    raise RuntimeError("%s: %s" % (method, message["error"]))
                return message.get("result", {})

    async def eval(self, expression):
        result = await self.call("Runtime.evaluate", expression=expression,
                                 returnByValue=True, awaitPromise=True)
        details = result.get("exceptionDetails")
        if details:
            raise RuntimeError("page error: %s"
                               % details.get("text", details))
        return result.get("result", {}).get("value")


async def wait_for(cdp, expression, *, timeout=20.0, what=""):
    """Poll a JS predicate. Polling, not a fixed sleep: the GUI fills itself
    from several requests and a sleep long enough to be safe is also long
    enough to be wrong on a slower run."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await cdp.eval("!!(%s)" % expression):
            return
        await asyncio.sleep(0.2)
    raise SystemExit("timed out waiting for %s" % (what or expression))


async def click(cdp, selector):
    await wait_for(cdp, "document.querySelector(%s)" % json.dumps(selector),
                   what="selector %s" % selector)
    # A real click through the element, so the GUI's own handlers run.
    await cdp.eval("document.querySelector(%s).click()"
                   % json.dumps(selector))


async def shoot(cdp, path, *, clip_selector=None, scale=2, pad=0,
                width=None, height=None):
    params = {"format": "png"}
    if clip_selector:
        selector = json.dumps(clip_selector)
        # The element is brought into view first, and the rect is read
        # viewport-relative afterwards. Document coordinates do not work
        # here: this GUI scrolls its panels in their own containers, so
        # window.scrollY stays 0 while the element sits far below the fold,
        # and captureBeyondViewport then renders a blank clip. That is how
        # the OpSec section came out as an empty rectangle.
        size = await cdp.eval(
            "(() => { const e = document.querySelector(%s);"
            " if (!e) return null; const r = e.getBoundingClientRect();"
            " return {width: r.width, height: r.height}; })()" % selector)
        if not size or size["width"] < 1 or size["height"] < 1:
            raise SystemExit("nothing to clip for %s" % clip_selector)
        # An element taller than the viewport cannot be scrolled fully into
        # it, so the viewport grows to fit rather than the shot being cut.
        needed = int(size["height"]) + 2 * pad + 40
        if width and height and needed > height:
            await cdp.call("Emulation.setDeviceMetricsOverride",
                           width=width, height=needed,
                           deviceScaleFactor=scale, mobile=False)
            await asyncio.sleep(0.4)
        await cdp.eval("document.querySelector(%s).scrollIntoView("
                       "{block: 'center', inline: 'nearest'})" % selector)
        await asyncio.sleep(0.4)
        rect = await cdp.eval(
            "(() => { const r = document.querySelector(%s)"
            ".getBoundingClientRect();"
            " return {x: r.x, y: r.y, width: r.width, height: r.height};"
            " })()" % selector)
        params["clip"] = {"x": max(rect["x"] - pad, 0),
                          "y": max(rect["y"] - pad, 0),
                          "width": rect["width"] + 2 * pad,
                          "height": rect["height"] + 2 * pad,
                          "scale": scale}
    else:
        params["captureBeyondViewport"] = True
    result = await cdp.call("Page.captureScreenshot", **params)
    import base64
    data = base64.b64decode(result["data"])
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return len(data)


async def run(args) -> int:
    import aiohttp

    chrome = find_chrome(args.chrome)
    port = free_port()
    profile = tempfile.mkdtemp(prefix="capture-gui-")
    # device-scale-factor is the point of the exercise: the page is laid out
    # at --width x --height and rasterised at that multiple, so text is
    # sharp at the size the documentation shows it.
    proc = subprocess.Popen(
        [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--no-first-run", "--no-default-browser-check",
         "--disable-extensions", "--mute-audio",
         "--user-data-dir=" + profile,
         "--force-device-scale-factor=%d" % args.scale,
         "--window-size=%d,%d" % (args.width, args.height),
         "--remote-debugging-port=%d" % port, "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        async with aiohttp.ClientSession() as session:
            ws_url = None
            for _ in range(100):
                try:
                    async with session.get(
                            "http://127.0.0.1:%d/json/list" % port) as reply:
                        tabs = await reply.json()
                    page = next((t for t in tabs if t.get("type") == "page"),
                                None)
                    if page:
                        ws_url = page["webSocketDebuggerUrl"]
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.1)
            if not ws_url:
                raise SystemExit("Chrome did not open a debugging port")

            async with session.ws_connect(ws_url, max_msg_size=0) as ws:
                cdp = Cdp(session, ws)
                await cdp.call("Page.enable")
                await cdp.call("Runtime.enable")
                await cdp.call("Emulation.setDeviceMetricsOverride",
                               width=args.width, height=args.height,
                               deviceScaleFactor=args.scale, mobile=False)
                await cdp.call("Page.navigate", url=args.url)
                await wait_for(cdp, "document.readyState === 'complete'",
                               what="the page to load")
                if args.ready:
                    await wait_for(cdp, args.ready, timeout=args.timeout,
                                   what="--ready expression")
                for kind, value in args.steps:
                    if kind == "click":
                        await click(cdp, value)
                    elif kind == "wait":
                        await wait_for(cdp, value, timeout=args.timeout,
                                       what=value)
                    elif kind == "sleep":
                        await asyncio.sleep(float(value))
                    elif kind == "eval":
                        await cdp.eval(value)
                    elif kind == "hide":
                        # Toast notifications sit over the panels they
                        # describe; removing them is honest, inventing the
                        # panel underneath would not be.
                        await cdp.eval(
                            "document.querySelectorAll(%s)"
                            ".forEach(e => e.style.display = 'none')"
                            % json.dumps(value))
                size = await shoot(cdp, args.out, clip_selector=args.clip,
                                   scale=args.scale, pad=args.pad,
                                   width=args.width, height=args.height)
                shot = await cdp.eval(
                    "JSON.stringify({w: Math.round(document.documentElement"
                    ".getBoundingClientRect().width), t: document.title})")
                print("wrote %s (%d bytes) at scale %d; page %s"
                      % (args.out, size, args.scale, shot))
        return 0
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)
        shutil.rmtree(profile, ignore_errors=True)


class _Step(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        namespace.steps.append((option_string.lstrip("-"), value))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture the operator GUI at documentation quality")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True, help="PNG to write")
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1000)
    parser.add_argument("--scale", type=int, default=2,
                        help="device pixel ratio; 2 is a retina rendering")
    parser.add_argument("--clip", help="capture this element, not the viewport")
    parser.add_argument("--pad", type=int, default=12,
                        help="pixels of breathing room around --clip")
    parser.add_argument("--ready", help="JS that must be true before steps")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--chrome")
    for flag in ("--click", "--wait", "--sleep", "--eval", "--hide"):
        parser.add_argument(flag, action=_Step, dest="steps", default=[])
    args = parser.parse_args(argv)
    if not args.steps:
        args.steps = []
    return asyncio.get_event_loop().run_until_complete(run(args))


if __name__ == "__main__":
    sys.exit(main())

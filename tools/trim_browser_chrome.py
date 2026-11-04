#!/usr/bin/env python3
"""Trim Chrome's window off a documentation still.

Fourteen of the figures taken before the agent layer are window grabs:
the tab strip, the toolbar, and the address bar reading `localhost:8443`.
The newer ones are page captures, taken through tools/capture_gui.py, so
the documentation showed two visibly different kinds of figure.

Re-shooting them was the obvious answer and turned out to be the wrong
one. The old figures were staged with content the live lab does not have:
the old loot vault holds etc_shadow.zip, ntds.dit and kerberos_tickets.zip
where a fresh capture holds whatever this machine happens to have, and the
old terminal shows real command output where a fresh one shows an idle
session. Re-shooting them all would have made the documentation worse. So
the content is kept and only the window is removed.

    python3 tools/trim_browser_chrome.py docs/screenshots/*.png

Only files that actually have the window are modified, and the detection
is in the test suite: cropping 80 pixels off a page capture would take the
application's own header with it.
"""

import argparse
import pathlib
import sys

from PIL import Image

# Measured off the committed grabs, all of which came from the same window
# at the same zoom: tab strip to y=46, toolbar to y=80, page below.
TAB_STRIP = 46
CHROME_HEIGHT = 80

# A band change this large is an edge rather than a gradient. Both edges
# have to be present: a single horizontal rule near the top of a page is
# not a browser, and treating it as one would crop the header away.
_EDGE = 35


def _row_means(im, upto):
    out = []
    step = max(1, im.width // 24)
    for y in range(min(upto, im.height)):
        px = [im.getpixel((x, y)) for x in range(0, im.width, step)]
        out.append(tuple(sum(c[i] for c in px) // len(px) for i in range(3)))
    return out


def chrome_height(im):
    """Where Chrome's UI ends, or None if this is already a page capture."""
    im = im.convert("RGB")
    if im.height < CHROME_HEIGHT + 20:
        return None
    means = _row_means(im, CHROME_HEIGHT + 20)

    def edge(above, below):
        return abs(sum(means[above]) - sum(means[below])) > _EDGE

    if edge(TAB_STRIP - 2, TAB_STRIP + 2) and edge(CHROME_HEIGHT - 2,
                                                   CHROME_HEIGHT + 2):
        return CHROME_HEIGHT
    return None


def trim(path):
    """Crop in place. Returns True if the file was changed."""
    path = pathlib.Path(path)
    with Image.open(path) as im:
        height = chrome_height(im)
        if height is None:
            return False
        cropped = im.convert("RGB").crop((0, height, im.width, im.height))
    cropped.save(path)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    changed = 0
    for name in args.files:
        path = pathlib.Path(name)
        if args.dry_run:
            with Image.open(path) as im:
                height = chrome_height(im)
            print("  %-34s %s" % (path.name,
                                  "would trim %d px" % height if height
                                  else "page capture, left alone"))
            continue
        if trim(path):
            print("  %-34s trimmed" % path.name)
            changed += 1
        else:
            print("  %-34s page capture, left alone" % path.name)
    if not args.dry_run:
        print("%d of %d changed" % (changed, len(args.files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

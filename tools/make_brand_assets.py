#!/usr/bin/env python3
"""Cut the raccoon's face out of the wallpaper and build the brand assets.

    python3 tools/make_brand_assets.py          # write the assets
    python3 tools/make_brand_assets.py --check  # verify, write nothing

The header used to serve `static/trashpanda_logo.png`, which is a 677x369
banner of a round badge on a white field, into a 38x38 box with
`border-radius:50%`. A 1.83:1 image forced into a square is squashed
horizontally, and the white margins then ate most of the circle: the
result was a flattened raccoon in a ring. The fix is a square source, and
the best one available is the face in the wallpaper.

**Nothing here is redrawn or invented.** The master is a crop at the
wallpaper's own resolution -- the same pixels, moved -- and every smaller
size is an exact 2x2 average of the one above it, halving 256 to 16. That
averaging is written out here rather than handed to a library so the
property is provable: `tools/` has no image dependency, and
`software/tests/test_brand_assets.py` re-derives the chain with its own
PNG reader and compares.

The one place pixels *are* invented is `raccoon_face_512.png`, which is a
Lanczos upscale for slides and READMEs. It is named and documented as
such, and it carries no detail the 256 does not: 256x256 is all there is.

Pillow is used for two things only -- decoding the source JPEG, which
cannot be done in the standard library, and that upscale. It is a
development dependency and deliberately not declared in either
requirements file: this script generates committed assets and nothing at
runtime needs it.
"""

import argparse
import pathlib
import struct
import sys
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCE = REPO / "static" / "wallpaper.jpg"

# Where the face is, in the wallpaper's own pixels. Chosen so the eyes land
# at 33%/44% and 57%/45%, which is the framing the badge and the favicon
# both read well at, and so the crop is 256 wide -- that makes every
# favicon size an exact halving rather than a resample.
FACE_BOX = (698, 140, 954, 396)

# Brand assets: the master and the upscale, for READMEs and slides. The
# master is deliberately *not* copied into the served directory -- the page
# links nothing bigger than 128, and a second copy of a 166 kB file is a
# second thing that can drift.
BRAND_DIR = REPO / "static"
# What the operator page links. Served by `/static/<path>` on the operator
# socket, which is loopback.
WEB_DIR = REPO / "software" / "c2" / "static"

MASTER = "raccoon_face_256.png"
UPSCALE = "raccoon_face_512.png"
# 128 is what the header shows at 38 logical pixels, which covers a
# 3x display; 64 is the favicon's working size, and 32 and 16 are the
# sizes a browser actually picks for a tab and a bookmark.
WEB_SIZES = (128, 64, 32, 16)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify the committed assets, write nothing")
    args = parser.parse_args(argv)

    try:
        from PIL import Image
    except ImportError:
        print("This script needs Pillow, which is a development dependency "
              "and is deliberately not in either requirements file:\n"
              "    python3 -m pip install --user Pillow\n"
              "Nothing at runtime needs it; the assets it writes are "
              "committed.", file=sys.stderr)
        return 2

    if not SOURCE.exists():
        print("the source wallpaper is missing: %s" % SOURCE, file=sys.stderr)
        return 1

    face = Image.open(SOURCE).convert("RGB").crop(FACE_BOX)
    if face.size != (256, 256):
        print("FACE_BOX is %s, which crops %s and not 256x256"
              % (FACE_BOX, face.size), file=sys.stderr)
        return 1

    master = _Raster(face.size[0], face.size[1],
                     bytes(b for px in face.getdata() for b in px))
    chain = {256: master}
    size = 256
    while size > 16:
        size //= 2
        chain[size] = chain[size * 2].halved()

    left, right = _eyes(master)
    print("  eyes, normalised to the master:")
    for name, (x, y, r) in (("left", left), ("right", right)):
        print("    %-6s centre %.4f, %.4f   radius %.4f"
              % (name, x, y, r))

    written = []
    if args.check:
        _check(chain, written)
    else:
        _write(BRAND_DIR / MASTER, chain[256], written)
        face.resize((512, 512), Image.LANCZOS).save(BRAND_DIR / UPSCALE)
        written.append(str((BRAND_DIR / UPSCALE).relative_to(REPO)))
        for size in WEB_SIZES:
            _write(WEB_DIR / ("favicon-%d.png" % size), chain[size], written)

    for path in written:
        print("  %s" % path)
    return 0


def _write(path, raster, written):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raster.to_png())
    written.append(str(path.relative_to(REPO)))


def _check(chain, written):
    for path, size in ((BRAND_DIR / MASTER, 256),
                       *[(WEB_DIR / ("favicon-%d.png" % s), s)
                         for s in WEB_SIZES]):
        state = "missing"
        if path.exists():
            state = "matches" if path.read_bytes() == chain[size].to_png() \
                else "DIFFERS from the source crop"
        written.append("%-44s %s" % (path.relative_to(REPO), state))


def _eyes(master):
    """Find the two glowing eyes, as fractions of the master's size.

    Reported rather than assumed: the favicon animation needs to know
    where to put its glow, and a crop that moves must move the glow with
    it. The page carries these numbers as constants and a test re-derives
    them from the committed favicon, so the two cannot drift.
    """
    # Searched inside a band, not across the whole crop. The picture is
    # red all over -- a glowing USB stick, lock picks, the background --
    # so a free search for "bright red" found a cluster with a radius of
    # 0.42 of the image, which is not an eye. The band says where a face's
    # eyes are in this framing; the checks below say whether what was
    # found looks like two of them.
    x0, x1 = int(master.width * 0.20), int(master.width * 0.70)
    y0, y1 = int(master.height * 0.35), int(master.height * 0.55)
    hits = []
    for y in range(y0, y1):
        for x in range(x0, x1):
            r, g, b = master.pixel(x, y)
            if r > 225 and g < 150 and b < 150 and r - max(g, b) > 90:
                hits.append((x, y))
    if not hits:
        raise SystemExit("no glowing eyes found in the crop")
    columns = sorted({x for x, _ in hits})
    gaps = [(b - a, a) for a, b in zip(columns, columns[1:]) if b - a > 4]
    if not gaps:
        raise SystemExit("the red pixels form one cluster, not two eyes")
    split = max(gaps)[1]
    out = []
    for group in ([p for p in hits if p[0] <= split],
                  [p for p in hits if p[0] > split]):
        xs = [p[0] for p in group]
        ys = [p[1] for p in group]
        cx = (min(xs) + max(xs)) / 2
        cy = (min(ys) + max(ys)) / 2
        radius = max(max(xs) - min(xs), max(ys) - min(ys)) / 2
        out.append((cx / master.width, cy / master.height,
                    radius / master.width))

    # Two eyes, side by side, roughly the same size. Checked rather than
    # trusted: this returns the coordinates the favicon's glow is drawn
    # at, and a wrong pair would put the glow on the fur.
    (lx, ly, lr), (rx, ry, rr) = out
    if abs(ly - ry) > 0.02:
        raise SystemExit("the two clusters are not level: %.3f vs %.3f"
                         % (ly, ry))
    if not 0.05 < rx - lx < 0.40:
        raise SystemExit("the clusters are %.3f apart, which is not a face"
                         % (rx - lx))
    for radius in (lr, rr):
        if not 0.01 < radius < 0.08:
            raise SystemExit("a cluster has radius %.3f, which is not an eye"
                             % radius)
    return out


class _Raster:
    """An 8-bit RGB image, and the two operations this script needs."""

    def __init__(self, width, height, data):
        self.width = width
        self.height = height
        self.data = data

    def pixel(self, x, y):
        i = (y * self.width + x) * 3
        return self.data[i], self.data[i + 1], self.data[i + 2]

    def halved(self):
        """Each output pixel is the mean of a 2x2 block. Nothing else.

        Written out instead of calling a resize, because "every size is an
        exact average of the one above it" is a property worth being able
        to check, and a library's filter choice is not.
        """
        if self.width % 2 or self.height % 2:
            raise ValueError("cannot halve %dx%d exactly"
                             % (self.width, self.height))
        w, h = self.width // 2, self.height // 2
        out = bytearray(w * h * 3)
        for y in range(h):
            for x in range(w):
                for channel in range(3):
                    total = 0
                    for dy in (0, 1):
                        for dx in (0, 1):
                            total += self.data[
                                ((y * 2 + dy) * self.width
                                 + (x * 2 + dx)) * 3 + channel]
                    # Rounded to nearest, so the chain does not drift
                    # darker with every halving.
                    out[(y * w + x) * 3 + channel] = (total + 2) // 4
        return _Raster(w, h, bytes(out))

    def to_png(self):
        raw = bytearray()
        for y in range(self.height):
            raw.append(0)                       # filter: none
            start = y * self.width * 3
            raw += self.data[start:start + self.width * 3]
        return (b"\x89PNG\r\n\x1a\n"
                + _chunk(b"IHDR", struct.pack(">IIBBBBB", self.width,
                                              self.height, 8, 2, 0, 0, 0))
                + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                + _chunk(b"IEND", b""))


def _chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Build the brand assets from the committed raccoon artwork.

    python3 tools/make_brand_assets.py          # write the assets
    python3 tools/make_brand_assets.py --check  # verify, write nothing

The artwork is `static/logo.gif`: the raccoon in a beret holding a glowing
USB stick, 443x394, eight frames of 180 ms, with a transparent background.
It is committed verbatim and is the only source; every PNG this script
writes is derived from it and can be regenerated pixel for pixel.

**The still frame is frame 4.** It is the brightest of the eight -- the
stick's glow is at its peak -- and the one that reads best when it is the
only frame anyone sees, which is what a favicon at rest, a README and a
slide are. The script measures that rather than trusting it: if the
artwork is replaced by one whose brightest frame is a different one, it
stops and says so.

**Why the resampling is premultiplied.** The GIF marks its background
with a transparent palette entry, but the colour *under* that
transparency is not black or white; it is (224, 106, 108), a pink. Every
transparent pixel carries it. A resize that averages the raw channels
mixes that pink into every pixel on the outline, and the raccoon comes
out with a salmon halo that no amount of alpha cleans up afterwards. So
the RGB of every transparent pixel is zeroed first -- that is the whole
of premultiplying, because GIF alpha is binary, 0 or 255 -- the Lanczos
filter runs on that, and the colour is divided back out by alpha only
when the PNG is written. Only the generated PNGs carry intermediate
alpha; the source never does.

The frame is 443x394 and the assets are square, so each frame is centred
on a transparent 443x443 canvas first (the picture sits 24 px down).
Nothing is cropped and nothing is stretched.

**Nothing here is redrawn.** The one place pixels are invented is
`logo_512.png`, which is a Lanczos upscale of the still frame for slides
and READMEs. It is named and documented as such, and it carries no detail
the artwork does not: 443 px is all there is.

Pillow is used to decode the GIF and to resample. It is a development
dependency, declared in tools/requirements.txt and deliberately in
neither of the runtime requirements files: this script generates
committed assets and nothing at runtime needs it. Only the PNG
*container* is independent of it: the encoder below is written out, so
the file's structure does not depend on Pillow. The *pixels* do. They
come from Pillow's Lanczos filter, and a Pillow that resamples
differently would write different ones.

`--check` is built around that split. It compares what a PNG means -- its
header fields and its decompressed scanlines -- and never the compressed
bytes, which depend on which zlib compressed them (zlib-ng, shipped by
some Python builds, deflates the same input differently) and say nothing
about the picture. So a different zlib cannot make it report a difference.
A different Pillow can, and when it does the message says so, because from
the pixels alone that is indistinguishable from an asset edited by hand.
"""

import argparse
import pathlib
import struct
import sys
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCE = REPO / "static" / "logo.gif"

FRAME_COUNT = 8
# The brightest frame, measured below and not merely believed.
STILL_FRAME = 4

# Brand assets: the master and the upscale, for READMEs and slides. The
# master is deliberately *not* copied into the served directory -- the page
# links nothing bigger than 128, and a second copy of a large file is a
# second thing that can drift.
BRAND_DIR = REPO / "static"
# What the operator page links. Served by `/static/<path>` on the operator
# socket, which is loopback.
WEB_DIR = REPO / "software" / "c2" / "static"

MASTER = "logo_256.png"
UPSCALE = "logo_512.png"
MASTER_SIZE = 256
# 128 is the page's `apple-touch-icon`, the only thing that links it now
# that the header shows `/logo.gif` instead; 64 is the favicon's working
# size, and 32 and 16 are the sizes a browser actually picks for a tab and
# a bookmark.
WEB_SIZES = (128, 64, 32, 16)
# The tab's animation: all eight frames at the favicon's working size,
# side by side, in frame order. The page steps through it on the GIF's own
# 180 ms, drawing one cell at a time.
STRIP = "favicon-frames-64.png"
STRIP_CELL = 64


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify the committed assets, write nothing")
    args = parser.parse_args(argv)

    try:
        import PIL  # noqa: F401
    except ImportError:
        print("This script needs Pillow, which is a development dependency "
              "declared in tools/requirements.txt, and deliberately in "
              "neither runtime requirements file:\n"
              "    python3 -m pip install --user Pillow\n"
              "Nothing at runtime needs it; the assets it writes are "
              "committed.", file=sys.stderr)
        return 2

    if not SOURCE.exists():
        print("the source artwork is missing: %s" % SOURCE, file=sys.stderr)
        return 1

    try:
        frames = _frames()
    except ValueError as err:
        print(err, file=sys.stderr)
        return 1
    still = frames[STILL_FRAME]

    # path -> the bytes that belong there. Built once, so writing and
    # checking cannot disagree about what the assets are.
    assets = {BRAND_DIR / MASTER: _reduce(still, MASTER_SIZE).to_png(),
              BRAND_DIR / UPSCALE: _reduce(still, 2 * MASTER_SIZE).to_png()}
    strip = _strip(frames)
    assets[WEB_DIR / STRIP] = strip.to_png()
    for size in WEB_SIZES:
        # The 64 is the strip's own still cell, copied out, and not a
        # second reduction that merely happens to agree with it.
        raster = _cell(strip, STILL_FRAME) if size == STRIP_CELL \
            else _reduce(still, size)
        assets[WEB_DIR / ("favicon-%d.png" % size)] = raster.to_png()

    lines = []
    if args.check:
        ok = _check(assets, lines)
    else:
        ok = True
        for path, data in assets.items():
            _write(path, data, lines)

    for line in lines:
        print("  %s" % line)
    return 0 if ok else 1


def _frames():
    """All eight frames: squared, premultiplied, in mode `RGBa`.

    Mode `RGBa` is Pillow's name for premultiplied RGBA, and the reason it
    is used here is that `Image.resize` leaves it alone. On plain `RGBA`
    Pillow premultiplies and unpremultiplies *itself* around a resize,
    which is the right idea, but with its own rounding and not the
    rounding `_reduce` documents.
    """
    from PIL import Image

    frames = []
    sums = []
    with Image.open(SOURCE) as gif:
        count = getattr(gif, "n_frames", 1)
        for index in range(count):
            gif.seek(index)
            frame = gif.convert("RGBA")

            # Measured on the frame as decoded, transparent pink included:
            # it is the brightness of the artwork as it is committed.
            sums.append(sum(frame.getchannel("R").tobytes()))

            levels = {level for _, level
                      in frame.getchannel("A").getcolors()}
            if not levels <= {0, 255}:
                raise ValueError("frame %d has alpha levels %s; the GIF is "
                                 "supposed to be binary"
                                 % (index, sorted(levels)))

            side = max(frame.size)
            canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
            canvas.paste(frame, ((side - frame.width) // 2,
                                 (side - frame.height) // 2))

            data = bytearray(canvas.tobytes())
            for i in range(0, len(data), 4):
                if data[i + 3] == 0:
                    data[i] = data[i + 1] = data[i + 2] = 0
            frames.append(Image.frombytes("RGBa", canvas.size, bytes(data)))

    if len(frames) != FRAME_COUNT:
        raise ValueError("the artwork has %d frames, not %d"
                         % (len(frames), FRAME_COUNT))
    if sums.index(max(sums)) != STILL_FRAME:
        raise ValueError("frame %d is not the brightest; the red-channel "
                         "sums are %s, and the brightest is frame %d"
                         % (STILL_FRAME, sums, sums.index(max(sums))))
    return frames


def _reduce(image, size):
    """Lanczos-resample a premultiplied image to `size` square.

    Called a reduction because it almost always is one; for the 512 it is
    the upscale. Either way it is one resample of the source's own pixels,
    never a resample of a resample. The result is unpremultiplied here, at
    the last moment, rounding to nearest:

        c = min(255, (c * 255 + a // 2) // a)      where a > 0
        c = 0                                      where a == 0
    """
    from PIL import Image

    small = image.resize((size, size), Image.LANCZOS)
    data = small.tobytes()
    out = bytearray(len(data))
    for i in range(0, len(data), 4):
        a = data[i + 3]
        if a:
            for channel in range(3):
                out[i + channel] = min(
                    255, (data[i + channel] * 255 + a // 2) // a)
            out[i + 3] = a
    return _Raster(size, size, bytes(out))


def _strip(frames):
    """The animation as one image: cell *i* is frame *i*, `STRIP_CELL` square.

    Each cell is `_reduce(frames[i], STRIP_CELL)` -- one Lanczos pass over
    that frame's own pixels, unpremultiplied at the end -- so no cell is
    ever a resample of another, and the cells are exactly what a lone
    favicon of that frame would be. A strip is a single file because the
    browser fetches one URL, and the page can cut it up on a canvas with no
    eight-way race between loads.
    """
    cells = [_reduce(frame, STRIP_CELL) for frame in frames]
    stride = STRIP_CELL * 4
    data = bytearray()
    for y in range(STRIP_CELL):
        for cell in cells:
            data += cell.data[y * stride:(y + 1) * stride]
    return _Raster(STRIP_CELL * len(cells), STRIP_CELL, bytes(data))


def _cell(strip, index):
    """One cell of a strip, copied out as a `STRIP_CELL` square raster.

    This is how the still favicon is made. It is a copy and not its own
    `_reduce` of the still frame: the two would come out the same today,
    but only a copy keeps the tab's resting icon and the animation's
    brightest frame identical by construction, however either is later
    changed.
    """
    stride = strip.width * 4
    step = STRIP_CELL * 4
    data = b"".join(
        strip.data[y * stride + index * step:y * stride + (index + 1) * step]
        for y in range(STRIP_CELL))
    return _Raster(STRIP_CELL, STRIP_CELL, data)


def _write(path, data, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    lines.append(str(path.relative_to(REPO)))


def _check(assets, lines):
    ok = True
    differs = False
    for path, data in assets.items():
        state = "missing"
        if path.exists():
            if _meaning(path.read_bytes()) == _meaning(data):
                state = "matches"
            else:
                state = "DIFFERS from the artwork"
                differs = True
        ok = ok and state == "matches"
        lines.append("%-44s %s" % (path.relative_to(REPO), state))
    if differs:
        lines.append("A file differing means one of two things: it was "
                     "edited since it was generated, or the installed "
                     "Pillow resampled differently from the one that "
                     "generated the committed files. Compressed bytes are "
                     "not compared, so a different zlib is not the cause.")
    return ok


def _meaning(png):
    """What a PNG says, without how it was compressed.

    The IHDR fields and the decompressed IDAT stream -- the scanlines, each
    behind its filter byte. Everything zlib decides is gone by then: two
    files that differ only in compression level, in zlib build, or in how
    the deflate stream was split across IDAT chunks come out equal. Chunk
    CRCs and ancillary chunks are not compared; they carry no pixels.

    A file that is not a PNG this generator could have written -- a bad
    signature, a truncated chunk, a stream that does not inflate -- comes
    out as `None`, which equals nothing but another `None`; the expected
    side is always a real PNG, so a damaged file reads as differing.
    """
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    header = None
    idat = bytearray()
    offset = 8
    while offset + 8 <= len(png):
        length, kind = struct.unpack(">I4s", png[offset:offset + 8])
        payload = png[offset + 8:offset + 8 + length]
        if len(payload) != length:
            return None
        if kind == b"IHDR":
            header = payload
        elif kind == b"IDAT":
            idat += payload
        offset += 12 + length
    if header is None:
        return None
    try:
        return header, zlib.decompress(bytes(idat))
    except zlib.error:
        return None


class _Raster:
    """An 8-bit RGBA image: four bytes a pixel, and a PNG encoder."""

    def __init__(self, width, height, data):
        self.width = width
        self.height = height
        self.data = data

    def pixel(self, x, y):
        i = (y * self.width + x) * 4
        return tuple(self.data[i:i + 4])

    def to_png(self):
        raw = bytearray()
        stride = self.width * 4
        for y in range(self.height):
            raw.append(0)                       # filter: none
            raw += self.data[y * stride:(y + 1) * stride]
        return (b"\x89PNG\r\n\x1a\n"
                + _chunk(b"IHDR", struct.pack(">IIBBBBB", self.width,
                                              self.height, 8, 6, 0, 0, 0))
                + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                + _chunk(b"IEND", b""))


def _chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))


if __name__ == "__main__":
    sys.exit(main())

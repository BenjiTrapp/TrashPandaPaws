#!/usr/bin/env python3
"""Assemble captured frames into a GIF that can actually be read.

Why this exists rather than one ffmpeg command: a tour of the operator GUI
has to hold each screen long enough to take in, and ffmpeg has no way to
give one frame a longer delay than another. The obvious workaround --
repeating a frame to hold it -- was measured at about 33 KB per repeat,
which is most of the cost of showing a fresh screen, so a readable tour
would have cost several times what it needs to.

The GIF format stores the delay in each frame's Graphic Control Extension.
So the frames are encoded once by ffmpeg, which compresses a screenshot
palette far better than Pillow's encoder does (about 108 KB per screen
against 281), and the delays are written into the finished file
afterwards. One frame per screen, any hold time, no repeats.

    python3 tools/make_gif.py --manifest frames.txt \
        --out docs/screenshots/c2_tour.gif --width 1200

The manifest is one line per frame, `name.png <seconds>`, resolved next to
the manifest itself -- which is what the capture step writes out.

Needs ffmpeg, which is on the machine, and Pillow, which is declared in
tools/requirements.txt. gifsicle would optimise further and is
deliberately not required.
"""

import argparse
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

from PIL import Image

# A screenshot is flat UI colour, so dithering only adds noise that the
# LZW stage then cannot compress: measured 25% larger and visibly worse on
# text. Fewer colours than this starts to band the syntax highlighting.
DEFAULT_COLOURS = 128

# The GUI's own background, so a frame of a different shape is padded with
# something that reads as part of the page rather than as a letterbox.
PAD = (13, 15, 20)


def _normalise(frames, width, work):
    """Write every frame at one size, which is what ffmpeg requires.

    Its image2 demuxer stops at the first frame whose dimensions differ
    from the one before and says nothing: the run exits 0 and leaves a
    one-frame GIF. The existing screenshots are 1233x963, 1229x956 and
    1640x571 among others, so this is not a hypothetical.

    The canvas is as tall as the tallest frame once scaled to the full
    width, and each frame is fitted inside it without changing its aspect
    ratio -- a stretched screenshot is illegible, which would defeat the
    purpose.
    """
    opened = []
    for path, _ in frames:
        if not os.path.isfile(path):
            raise FileNotFoundError("no such frame: %s" % path)
        opened.append(Image.open(path).convert("RGB"))

    height = max(round(im.height * width / im.width) for im in opened)
    # An odd dimension is legal in a GIF but trips several encoders that
    # the figures may later be run through.
    height += height % 2

    out = []
    for index, im in enumerate(opened):
        scale = min(width / im.width, height / im.height)
        size = (max(1, round(im.width * scale)), max(1, round(im.height * scale)))
        canvas = Image.new("RGB", (width, height), PAD)
        canvas.paste(im.resize(size, Image.LANCZOS),
                     ((width - size[0]) // 2, (height - size[1]) // 2))
        target = work / ("%04d.png" % index)
        canvas.save(target)
        out.append(target)
    return out


def _encode(count, work, colours):
    """One frame per screen, via ffmpeg's two-pass palette."""
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise RuntimeError("ffmpeg is not on PATH; it does the encoding")
    gif = work / "out.gif"
    chain = ("split[s0][s1];[s0]palettegen=max_colors=%d[p];"
             "[s1][p]paletteuse=dither=none" % colours)
    result = subprocess.run(
        [ffmpeg, "-loglevel", "error", "-y", "-framerate", "1",
         "-i", str(work / "%04d.png"), "-vf", chain, "-loop", "0", str(gif)],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError("ffmpeg failed: %s" % result.stderr.strip())
    return gif


def _set_delays(data, hundredths):
    """Rewrite each frame's delay, walking the block structure.

    Searching for the `21 F9 04` introducer would be shorter and wrong:
    those bytes occur inside LZW image data often enough to corrupt a
    file now and then, and a corrupt GIF fails silently in some viewers
    and not others. So the blocks are walked properly.
    """
    buf = bytearray(data)
    if buf[:3] != b"GIF":
        raise ValueError("not a GIF")
    pos = 13
    flags = buf[10]
    if flags & 0x80:  # global colour table
        pos += 3 * (2 ** ((flags & 0x07) + 1))

    def skip_sub_blocks(at):
        while buf[at]:
            at += 1 + buf[at]
        return at + 1

    frame = 0
    while pos < len(buf):
        marker = buf[pos]
        if marker == 0x3B:  # trailer
            break
        if marker == 0x21:  # extension
            label = buf[pos + 1]
            if label == 0xF9:  # graphic control
                if frame >= len(hundredths):
                    raise ValueError("more frames in the file than hold times")
                struct.pack_into("<H", buf, pos + 4, hundredths[frame])
                frame += 1
            pos = skip_sub_blocks(pos + 2)
            continue
        if marker == 0x2C:  # image descriptor
            local = buf[pos + 9]
            pos += 10
            if local & 0x80:
                pos += 3 * (2 ** ((local & 0x07) + 1))
            pos += 1  # LZW minimum code size
            pos = skip_sub_blocks(pos)
            continue
        raise ValueError("unexpected block 0x%02X at %d" % (marker, pos))

    if frame != len(hundredths):
        raise ValueError("wrote %d delays for %d frames"
                         % (frame, len(hundredths)))
    return bytes(buf)


def build(frames, out, width=1200, colours=DEFAULT_COLOURS):
    """`frames` is [(png path, hold in seconds)]. Returns bytes written."""
    if not frames:
        raise ValueError("no frames to build from")
    hundredths = []
    for path, hold in frames:
        if hold is None or hold <= 0:
            raise ValueError(
                "frame %s has a hold of %r; a zero delay means 'as fast as "
                "possible' in some viewers and 100ms in others, so the "
                "result would play differently per browser" % (path, hold))
        hundredths.append(max(1, round(hold * 100)))

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        _normalise(frames, width, work)
        gif = _encode(len(frames), work, colours)
        patched = _set_delays(gif.read_bytes(), hundredths)

    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(out).write_bytes(patched)
    return len(patched)


def _read_manifest(path):
    base = pathlib.Path(path).resolve().parent
    frames = []
    for number, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, hold = line.rpartition(" ")
        if not name:
            raise ValueError("line %d of the manifest has no hold time: %r"
                             % (number, line))
        frames.append((str(base / name.strip()), float(hold)))
    return frames


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True,
                        help="one line per frame: name.png <seconds>")
    parser.add_argument("--out", required=True)
    parser.add_argument("--width", type=int, default=1200)
    parser.add_argument("--colours", "--colors", type=int,
                        default=DEFAULT_COLOURS, dest="colours")
    args = parser.parse_args(argv)

    frames = _read_manifest(args.manifest)
    written = build(frames, args.out, args.width, args.colours)
    seconds = sum(hold for _, hold in frames)
    print("%s: %d frame%s, %.1f s, %d KB"
          % (args.out, len(frames), "" if len(frames) == 1 else "s",
             seconds, written // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())

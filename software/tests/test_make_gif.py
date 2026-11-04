"""The GIF builder: a frame sequence plus hold times, assembled.

Why this is tested where tools/capture_gui.py is not: capture_gui drives a
browser, so a unit test of it would be assertions about a mocked DevTools
protocol and would pass whatever the browser did. This is a pure
transformation -- PNGs in, one GIF out -- and every property worth having
is readable back out of the file.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from PIL import Image

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from tools import make_gif


def _png(path, size=(400, 300), colour=(20, 30, 40), bar=None):
    """A frame with enough structure that a palette has work to do."""
    im = Image.new("RGB", size, colour)
    if bar is not None:
        im.paste((220, 200, 120), (0, bar, size[0], min(bar + 40, size[1])))
    im.save(path)
    return str(path)


def _delays(path):
    """Per-frame delays in milliseconds, read back from the file."""
    out = []
    with Image.open(path) as im:
        try:
            while True:
                out.append(im.info.get("duration"))
                im.seek(im.tell() + 1)
        except EOFError:
            pass
    return out


def _sizes(path):
    """The dimensions of every frame, which must all agree."""
    seen = set()
    with Image.open(path) as im:
        try:
            while True:
                seen.add(im.size)
                im.seek(im.tell() + 1)
        except EOFError:
            pass
    return seen


class TestHoldingAFrameCostsNoExtraFrames(unittest.TestCase):
    """The whole reason this exists instead of a bare ffmpeg call.

    ffmpeg cannot set a per-frame delay, so the obvious way to hold a
    screen is to repeat its frame -- measured at ~33 KB each, which is
    most of the cost of a fresh screen. The GIF format stores the delay
    per frame, so a long hold is one frame with a large delay. These
    tests pin that: the frame count follows the number of screens, never
    the duration.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_one_frame_per_screen_however_long_it_is_held(self):
        frames = [(_png(self.dir / "a.png", bar=10), 4.0),
                  (_png(self.dir / "b.png", bar=120), 4.0),
                  (_png(self.dir / "c.png", bar=240), 4.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=200)
        self.assertEqual(len(_delays(out)), 3)

    def test_each_hold_time_arrives_in_the_file(self):
        frames = [(_png(self.dir / "a.png", bar=10), 0.5),
                  (_png(self.dir / "b.png", bar=120), 3.0),
                  (_png(self.dir / "c.png", bar=240), 1.25)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=200)
        self.assertEqual(_delays(out), [500, 3000, 1250])

    def test_a_long_hold_does_not_cost_more_than_a_short_one(self):
        short = [(_png(self.dir / "a.png", bar=10), 0.2),
                 (_png(self.dir / "b.png", bar=120), 0.2)]
        out_short = str(self.dir / "short.gif")
        out_long = str(self.dir / "long.gif")
        make_gif.build(short, out_short, width=200)
        make_gif.build([(p, 10.0) for p, _ in short], out_long, width=200)
        self.assertEqual(os.path.getsize(out_short),
                         os.path.getsize(out_long))

    def test_the_gif_loops(self):
        frames = [(_png(self.dir / "a.png", bar=10), 1.0),
                  (_png(self.dir / "b.png", bar=99), 1.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=200)
        with Image.open(out) as im:
            self.assertEqual(im.info.get("loop"), 0)


class TestFramesOfDifferentSizesAllSurvive(unittest.TestCase):
    """The defect that prompted the tool rather than a one-line command.

    ffmpeg's image2 demuxer stops at the first frame whose dimensions
    differ from the one before, and it says nothing about it: the run
    exits 0 and writes a one-frame GIF. The existing screenshots are
    1233x963, 1229x956 and 1640x571 among others, so stringing them
    together silently produced a single still.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_mismatched_inputs_all_reach_the_output(self):
        frames = [(_png(self.dir / "wide.png", size=(800, 300), bar=10), 1.0),
                  (_png(self.dir / "tall.png", size=(300, 800), bar=20), 1.0),
                  (_png(self.dir / "square.png", size=(500, 500), bar=30), 1.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=400)
        self.assertEqual(len(_delays(out)), 3)

    def test_every_frame_has_the_same_dimensions(self):
        frames = [(_png(self.dir / "wide.png", size=(800, 300), bar=10), 1.0),
                  (_png(self.dir / "tall.png", size=(300, 800), bar=20), 1.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=400)
        self.assertEqual(len(_sizes(out)), 1)

    def test_the_requested_width_is_the_width(self):
        frames = [(_png(self.dir / "a.png", size=(800, 300), bar=10), 1.0),
                  (_png(self.dir / "b.png", size=(800, 300), bar=99), 1.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=360)
        with Image.open(out) as im:
            self.assertEqual(im.size[0], 360)

    def test_an_aspect_ratio_is_not_stretched(self):
        # A frame whose shape differs from the canvas is padded, not
        # squashed: a stretched screenshot is illegible, which is the
        # whole point of the exercise. The 2:1 frame on a 1:1 canvas must
        # therefore leave rows that are entirely padding.
        frames = [(_png(self.dir / "wide.png", size=(800, 400),
                        colour=(90, 20, 20), bar=10), 1.0),
                  (_png(self.dir / "square.png", size=(400, 400),
                        colour=(20, 90, 20), bar=99), 1.0)]
        out = str(self.dir / "out.gif")
        make_gif.build(frames, out, width=400)
        with Image.open(out) as im:
            wide = im.convert("RGB")
        self.assertEqual(wide.size, (400, 400))
        top = {wide.getpixel((x, 1)) for x in range(0, 400, 7)}
        middle = {wide.getpixel((x, 200)) for x in range(0, 400, 7)}
        self.assertEqual(len(top), 1, "the padded row is not uniform")
        self.assertNotEqual(top, middle,
                            "nothing was padded, so it was stretched")


class TestItRefusesWhatItCannotBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_no_frames_is_an_error_not_an_empty_gif(self):
        with self.assertRaises(ValueError):
            make_gif.build([], str(self.dir / "out.gif"))

    def test_a_missing_frame_is_named_in_the_error(self):
        frames = [(_png(self.dir / "a.png"), 1.0),
                  (str(self.dir / "gone.png"), 1.0)]
        with self.assertRaises(FileNotFoundError) as caught:
            make_gif.build(frames, str(self.dir / "out.gif"))
        self.assertIn("gone.png", str(caught.exception))

    def test_a_hold_of_zero_is_refused(self):
        # A zero delay renders as "as fast as possible" in some viewers and
        # as 100ms in others, so the tour would play differently per
        # browser. Refused rather than silently clamped.
        frames = [(_png(self.dir / "a.png"), 0.0)]
        with self.assertRaises(ValueError):
            make_gif.build(frames, str(self.dir / "out.gif"))


class TestItRunsFromTheCommandLine(unittest.TestCase):
    """The capture step hands over a directory and a manifest, not a call."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_manifest_of_frames_and_holds_builds_the_gif(self):
        _png(self.dir / "01.png", bar=10)
        _png(self.dir / "02.png", bar=120)
        manifest = self.dir / "frames.txt"
        manifest.write_text("01.png 2.5\n02.png 0.75\n")
        out = self.dir / "out.gif"
        root = pathlib.Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "make_gif.py"),
             "--manifest", str(manifest), "--out", str(out), "--width", "200"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(_delays(str(out)), [2500, 750])

    def test_it_reports_what_it_wrote(self):
        _png(self.dir / "01.png", bar=10)
        manifest = self.dir / "frames.txt"
        manifest.write_text("01.png 1.0\n")
        out = self.dir / "out.gif"
        root = pathlib.Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "make_gif.py"),
             "--manifest", str(manifest), "--out", str(out), "--width", "200"],
            capture_output=True, text=True)
        self.assertIn("1 frame", result.stdout)
        self.assertIn("KB", result.stdout)


if __name__ == "__main__":
    unittest.main()

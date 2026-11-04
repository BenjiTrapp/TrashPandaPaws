"""Trimming the browser window off the older documentation stills.

Fourteen of the twenty-three figures taken before the agent layer are
window grabs: Chrome's tab strip, its toolbar, and the address bar reading
`localhost:8443`. The five newer ones are page captures, so the
documentation showed two visibly different kinds of figure.

Re-shooting them was the obvious answer and turned out to be the wrong
one: the old figures were staged with content the live lab does not have.
The old loot vault holds etc_shadow.zip, ntds.dit and kerberos_tickets.zip;
a freshly captured one holds whatever this machine happens to have. The old
terminal shows real command output; a fresh one shows an idle session. So
the content is kept and only the window is removed.

What is tested here is the detection, because that is what decides whether
a figure is modified at all -- cropping 80 pixels off a page capture would
take the application's own header with it.
"""

import pathlib
import sys
import tempfile
import unittest

from PIL import Image

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from tools import trim_browser_chrome as trim


def _bands(bands, width=600):
    """An image made of horizontal bands: [(height, (r,g,b)), ...]."""
    total = sum(h for h, _ in bands)
    im = Image.new("RGB", (width, total))
    y = 0
    for height, colour in bands:
        im.paste(colour, (0, y, width, y + height))
        y += height
    return im


# The bands these grabs actually have, measured off the committed files:
# tab strip, toolbar, then the page.
WINDOW = [(46, (62, 61, 60)), (34, (47, 46, 45)), (700, (13, 15, 20))]
PAGE = [(60, (18, 20, 26)), (720, (13, 15, 20))]


class TestAWindowGrabIsRecognised(unittest.TestCase):
    def test_the_measured_band_structure_is_found(self):
        self.assertEqual(trim.chrome_height(_bands(WINDOW)), 80)

    def test_a_page_capture_is_left_alone(self):
        self.assertIsNone(trim.chrome_height(_bands(PAGE)))

    def test_a_uniform_image_is_left_alone(self):
        self.assertIsNone(trim.chrome_height(_bands([(800, (13, 15, 20))])))

    def test_an_image_too_short_to_hold_the_bands_is_left_alone(self):
        self.assertIsNone(trim.chrome_height(_bands([(40, (62, 61, 60))])))

    def test_one_edge_is_not_enough(self):
        # A single horizontal rule somewhere near the top is not a browser.
        nearly = [(46, (62, 61, 60)), (34, (62, 61, 60)), (700, (13, 15, 20))]
        self.assertIsNone(trim.chrome_height(_bands(nearly)))


class TestTrimmingKeepsEverythingBelow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_the_page_survives_pixel_for_pixel(self):
        source = self.dir / "grab.png"
        im = _bands(WINDOW)
        # A mark inside the page, to prove the crop lands where it says.
        im.paste((200, 40, 40), (10, 80, 40, 90))
        im.save(source)
        trim.trim(source)
        with Image.open(source) as out:
            out = out.convert("RGB")
            self.assertEqual(out.height, 700)  # 46 + 34 chrome off 780
            self.assertEqual(out.getpixel((20, 5)), (200, 40, 40))

    def test_a_page_capture_is_not_touched(self):
        source = self.dir / "page.png"
        _bands(PAGE).save(source)
        before = source.read_bytes()
        self.assertFalse(trim.trim(source))
        self.assertEqual(source.read_bytes(), before)

    def test_it_reports_whether_it_changed_anything(self):
        grab = self.dir / "grab.png"
        _bands(WINDOW).save(grab)
        self.assertTrue(trim.trim(grab))
        # Idempotent: the result is a page capture, so a second run is a
        # no-op rather than another 80 pixels off the header.
        self.assertFalse(trim.trim(grab))


if __name__ == "__main__":
    unittest.main()

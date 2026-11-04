"""The storyboard a sequence capture runs, and the manifest it hands on.

The browser half of tools/capture_sequence.py is not tested here, for the
same reason tools/capture_gui.py is not tested at all: a unit test of it
would be assertions about a mocked DevTools protocol and would pass
whatever the browser actually did. What is tested is the part that decides
*what* gets shot and *how long each screen is held* -- a storyboard that
mis-parses silently would produce a plausible-looking GIF with the wrong
timing, and the only way to notice would be to watch all of it.
"""

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from tools import capture_sequence, make_gif


class TestAStoryboardIsReadStrictly(unittest.TestCase):
    """Every field is load-bearing, so a typo must stop the run.

    A storyboard is written by hand and read once, hours before anyone
    looks at the result. A misspelled key that is quietly ignored costs a
    full capture run to discover -- and the tour is the one artefact
    where a wrong hold time is invisible until you sit through it.
    """

    def test_a_step_needs_a_hold_time(self):
        with self.assertRaises(ValueError) as caught:
            capture_sequence.parse([{"caption": "Dashboard"}])
        self.assertIn("hold", str(caught.exception))

    def test_an_unknown_key_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            capture_sequence.parse([{"hold": 2.0, "captoin": "typo"}])
        self.assertIn("captoin", str(caught.exception))

    def test_a_hold_of_zero_is_refused_here_too(self):
        # make_gif refuses it as well; catching it at parse time means the
        # whole capture run is not spent first.
        with self.assertRaises(ValueError):
            capture_sequence.parse([{"hold": 0}])

    def test_the_minimum_step_is_just_a_hold(self):
        steps = capture_sequence.parse([{"hold": 1.5}])
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].hold, 1.5)
        self.assertIsNone(steps[0].js)
        self.assertIsNone(steps[0].caption)
        self.assertTrue(steps[0].shoot)

    def test_a_setup_step_takes_no_frame(self):
        # The first attempt had a step whose only job was to dismiss the
        # connect toasts, and it became frame 0 of the tour: a tenth of a
        # second of undismissed toasts at the very start. Setup steps act
        # on the page without being photographed.
        steps = capture_sequence.parse([
            {"hold": 0.1, "js": "clearToasts()", "shoot": False},
            {"hold": 3.0, "caption": "Dashboard"}])
        self.assertFalse(steps[0].shoot)
        self.assertTrue(steps[1].shoot)

    def test_only_the_shot_steps_reach_the_manifest(self):
        steps = capture_sequence.parse([
            {"hold": 0.1, "js": "setup()", "shoot": False},
            {"hold": 2.0, "caption": "One"},
            {"hold": 3.0, "caption": "Two"}])
        shot = [s for s in steps if s.shoot]
        manifest = capture_sequence.write_manifest(
            pathlib.Path(tempfile.mkdtemp()), ["0000.png", "0001.png"], shot)
        frames = make_gif._read_manifest(str(manifest))
        self.assertEqual([hold for _, hold in frames], [2.0, 3.0])

    def test_the_fields_arrive_as_given(self):
        steps = capture_sequence.parse([{
            "hold": 3.0, "js": "showLootViewer()", "caption": "Loot Vault",
            "wait": ".loot-row", "settle": 1.2}])
        step = steps[0]
        self.assertEqual((step.hold, step.js, step.caption, step.wait,
                          step.settle),
                         (3.0, "showLootViewer()", "Loot Vault",
                          ".loot-row", 1.2))

    def test_an_empty_storyboard_is_refused(self):
        with self.assertRaises(ValueError):
            capture_sequence.parse([])


class TestPlaceholdersAreFilledBeforeTheRun(unittest.TestCase):
    """A storyboard cannot know the beacon id; it is assigned at check-in.

    So the committed storyboard carries `BEACON_ID` and the capture run
    substitutes it. Substituting into the raw text before parsing, rather
    than into each field afterwards, keeps it working wherever a
    placeholder appears -- a `js` expression, a caption, a wait selector.
    """

    def test_a_placeholder_is_replaced_everywhere_it_appears(self):
        text = ('[{"hold": 1, "js": "selectAgent(\'{{BEACON_ID}}\')",'
                ' "caption": "{{BEACON_ID}} is live"}]')
        filled = capture_sequence.fill(text, {"BEACON_ID": "raccoon-bandit"})
        steps = capture_sequence.parse(json.loads(filled))
        self.assertEqual(steps[0].js, "selectAgent('raccoon-bandit')")
        self.assertEqual(steps[0].caption, "raccoon-bandit is live")

    def test_an_unfilled_placeholder_is_an_error_not_a_literal(self):
        # Shooting twenty frames against a beacon called BEACON_ID would
        # succeed at every step and produce a useless tour.
        text = '[{"hold": 1, "js": "selectAgent(\'{{BEACON_ID}}\')"}]'
        with self.assertRaises(ValueError) as caught:
            capture_sequence.fill(text, {})
        self.assertIn("BEACON_ID", str(caught.exception))

    def test_a_storyboard_without_placeholders_passes_through(self):
        text = '[{"hold": 1, "caption": "Dashboard"}]'
        self.assertEqual(capture_sequence.fill(text, {}), text)

    def test_a_value_that_would_break_the_json_is_refused(self):
        text = '[{"hold": 1, "caption": "{{BEACON_ID}}"}]'
        with self.assertRaises(ValueError):
            capture_sequence.fill(text, {"BEACON_ID": 'he said "hi"'})

    def test_capitalised_words_in_a_caption_are_not_placeholders(self):
        # The first attempt matched any run of capitals, so captions
        # mentioning SMB, LDAP, NTLM and MSSQL were all read as unfilled
        # placeholders and the capture refused to start. Delimiters, not
        # a guess at what looks like a name.
        text = ('[{"hold": 1, "caption": "NetExec — SMB, LDAP, WinRM '
                'and MSSQL"}, {"hold": 1, "caption": "LLMNR and NBT-NS"}]')
        self.assertEqual(capture_sequence.fill(text, {}), text)


class TestTheManifestIsWhatMakeGifReads(unittest.TestCase):
    """The two tools meet at a text file, so the format is a contract.

    They were written together, which is exactly when an informal format
    drifts: one side starts quoting names, or writing holds in
    milliseconds, and the GIF comes out with every screen held for a
    hundredth of a second. This builds a real GIF from a real manifest.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _frames(self, count=3):
        from PIL import Image
        names = []
        for i in range(count):
            path = self.dir / ("%04d.png" % i)
            im = Image.new("RGB", (200, 150), (20, 30, 40))
            im.paste((200, 180, 90), (0, 10 + i * 20, 200, 40 + i * 20))
            im.save(path)
            names.append(path.name)
        return names

    def test_a_written_manifest_builds_with_the_right_holds(self):
        names = self._frames(3)
        steps = capture_sequence.parse([{"hold": 2.5}, {"hold": 0.75},
                                        {"hold": 4.0}])
        manifest = capture_sequence.write_manifest(self.dir, names, steps)
        frames = make_gif._read_manifest(str(manifest))
        self.assertEqual([hold for _, hold in frames], [2.5, 0.75, 4.0])

    def test_the_gif_it_produces_has_those_delays(self):
        from PIL import Image
        names = self._frames(2)
        steps = capture_sequence.parse([{"hold": 2.0}, {"hold": 0.5}])
        manifest = capture_sequence.write_manifest(self.dir, names, steps)
        out = self.dir / "out.gif"
        make_gif.build(make_gif._read_manifest(str(manifest)), str(out),
                       width=200)
        delays = []
        with Image.open(out) as im:
            try:
                while True:
                    delays.append(im.info.get("duration"))
                    im.seek(im.tell() + 1)
            except EOFError:
                pass
        self.assertEqual(delays, [2000, 500])

    def test_a_frame_name_with_a_space_would_break_it_and_is_refused(self):
        # The manifest splits on the last space, so a name containing one
        # parses as a different file with a nonsense hold. Refused rather
        # than discovered as a missing-file error later.
        steps = capture_sequence.parse([{"hold": 1.0}])
        with self.assertRaises(ValueError):
            capture_sequence.write_manifest(self.dir, ["my frame.png"], steps)

    def test_a_mismatched_count_is_refused(self):
        steps = capture_sequence.parse([{"hold": 1.0}, {"hold": 1.0}])
        with self.assertRaises(ValueError):
            capture_sequence.write_manifest(self.dir, ["0000.png"], steps)


class TestTheCaptionIsPutOnThePageItself(unittest.TestCase):
    """Captions are rendered by the GUI, not drawn onto the PNG afterwards.

    Drawing text into the image would need a font file, pick its own
    colours and come out at a different weight from everything around it.
    Injecting a styled element means the caption is rasterised by the same
    browser at the same density as the rest of the shot.
    """

    def test_any_text_is_inert_because_it_is_json_encoded(self):
        # The property is that the caption cannot break out of the string
        # it sits in. Asserting on a pair of characters was the wrong
        # test: the element's own CSS legitimately ends with `';`. What
        # makes the text inert is that it arrives as JSON, so that is
        # what gets asserted, against inputs that would otherwise escape.
        for text in ("Operator's \"dashboard\"",
                     "back\\slash",
                     "line\nbreak",
                     "</script><script>alert(1)</script>",
                     "'; document.body.remove(); //"):
            js = capture_sequence.caption_js(text)
            self.assertIn(json.dumps(text), js, text)

    def test_the_text_is_the_only_place_it_appears(self):
        # If the raw text leaked in alongside its encoded form, the
        # encoding would not be protecting anything.
        text = "a\"b"
        js = capture_sequence.caption_js(text)
        self.assertNotIn(text, js.replace(json.dumps(text), ""))

    def test_clearing_the_caption_removes_the_element(self):
        self.assertIn("remove()", capture_sequence.caption_js(None))

    def test_the_caption_element_has_one_stable_id(self):
        # Set and clear have to agree on it, or captions pile up on the
        # page and every later frame carries all the earlier ones.
        marker = capture_sequence.CAPTION_ID
        self.assertIn(marker, capture_sequence.caption_js("x"))
        self.assertIn(marker, capture_sequence.caption_js(None))

    def test_a_caption_takes_space_rather_than_covering_content(self):
        # The GUI's shell is height:100vh, so a fixed bar at the bottom
        # sits on top of the command input -- which is part of the very
        # feature the terminal frames are meant to show. The shell is
        # shortened by the caption's height instead.
        js = capture_sequence.caption_js("Terminal")
        self.assertIn(capture_sequence.SHELL_SELECTOR, js)
        self.assertIn(str(capture_sequence.CAPTION_HEIGHT), js)
        self.assertIn("100vh -", js)

    def test_clearing_the_caption_gives_the_space_back(self):
        js = capture_sequence.caption_js(None)
        self.assertIn(capture_sequence.SHELL_SELECTOR, js)
        self.assertIn("100vh", js)
        self.assertNotIn("100vh -", js)


if __name__ == "__main__":
    unittest.main()

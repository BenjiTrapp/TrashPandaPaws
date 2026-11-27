#!/usr/bin/env python3
"""The bench: what a container can measure, and what it cannot.

There is no device. The human has none -- *"ich habe kein gerät zur Hand
dafür war der Docker Container gedacht"* -- so a container is the bench,
and stage 1 of this design splits into three honest parts:

  * **Measurable, and fully:** the scout's capture and parse cost per
    packet, the document handoff, the beacon's fresh-or-ignore rule, the
    arithmetic, and whether a small model answers in a form the validator
    accepts.
  * **Measurable only as a proxy:** latency. An arm64 container with
    `--cpus` and `--memory` limits approximates the Pi's four cores and
    4 GB, but not an A72's clock -- so every second it reports is
    **optimistic by a factor nobody here can pin down**, and the number is
    a bound rather than a result.
  * **Not measurable at all:** watts and thermals. A container cannot fix
    the absence of a board, and the risk is carried in the design's risk
    table instead of being quietly assumed away.

These tests are about the bench's honesty rather than about any number it
produces: that latency is reported as a bound, that watts and thermals are
named as unmeasurable with the reason, and that a bad model result is
reported as a measurement rather than swallowed.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import way_out_bench as bench


class TestWhatItWillNotPretendToKnow(unittest.TestCase):
    def test_watts_and_thermals_are_named_as_not_measurable(self):
        self.assertEqual(sorted(bench.NOT_MEASURABLE), ["thermals", "watts"])
        for name, reason in bench.NOT_MEASURABLE.items():
            with self.subTest(name=name):
                self.assertIn("no device", reason.lower())

    def test_they_are_in_the_report(self):
        report = bench.report(packets=20, rounds=20)
        self.assertEqual(report["not_measurable"], bench.NOT_MEASURABLE)

    def test_every_timing_is_marked_as_an_optimistic_bound(self):
        report = bench.report(packets=20, rounds=20)
        for key in ("parse", "handoff", "arithmetic"):
            with self.subTest(key=key):
                self.assertIn("caveat", report[key])
                self.assertIn("optimistic", report[key]["caveat"].lower())

    def test_the_report_is_json(self):
        json.dumps(bench.report(packets=20, rounds=20))


class TestWhatItMeasures(unittest.TestCase):
    def test_it_scratches_outside_tmp_even_where_tmp_is_the_default(self):
        # Forced, because the answer is platform-dependent and the rule is
        # not: macOS puts the default temp directory under /var/folders,
        # Linux puts it at /tmp, and the way-out reader refuses the second.
        # A test that only asked the host would pass on a Mac and measure
        # a disabled feature in the container.
        with mock.patch.object(bench.tempfile, "gettempdir",
                               lambda: "/tmp"):
            root = bench._scratch()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.assertFalse(root == "/tmp" or root.startswith("/tmp/"), root)

    def test_it_scratches_somewhere_the_way_out_reader_accepts(self):
        # The measurement's own first finding: `read_way_out_policy`
        # refuses a state directory under /tmp, and /tmp is the default
        # temp directory on Linux -- so the first container run measured a
        # *disabled* feature and reported the ungated path's numbers. A
        # bench that measures something other than the feature is worse
        # than no bench.
        from software.c2.beacon import read_way_out_policy
        root = bench._scratch()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        policy = read_way_out_policy({"enabled": True, "state_dir": root})
        self.assertTrue(policy["enabled"],
                        "the bench scratches in %r, which the way-out "
                        "reader refuses" % root)

    def test_the_parse_cost_is_per_packet_over_a_replayed_capture(self):
        got = bench.measure_parse(packets=80)
        self.assertEqual(got["packets"], 80)
        self.assertGreater(got["cpu_us_per_packet"], 0)
        # The evidence has to have been read, or the number is the cost of
        # doing nothing.
        self.assertEqual(got["flags"], ["dot1x_seen", "portal_answered"])

    def test_the_replay_exercises_every_parser_including_tls(self):
        # A review found the replay had no TLS frame in it at all, while
        # the design's reading column said "the frames are the five rows
        # of the evidence table". `_sni` is the one parser that walks
        # attacker-supplied length fields, and it was never measured.
        got = bench.measure_parse(packets=400)
        self.assertGreater(got["tls_destinations"], 0,
                           "no TLS handshake was parsed, so the one parser "
                           "that walks length fields was not measured")
        self.assertGreater(got["resolvers"], 0)
        self.assertGreater(got["credentials"], 0)

    def test_the_replay_is_distinct_and_not_seven_frames_in_a_loop(self):
        # The same finding's other half: with the same frames repeating,
        # every dedup list stays length 1 and every pending collection
        # stays size 1, so the number was the looping cost with none of
        # the reading cost that grows. On real traffic the lists fill.
        got = bench.measure_parse(packets=400)
        self.assertGreater(got["tls_destinations"], 1)
        self.assertGreater(got["resolvers"], 1)
        # And the bounds hold, which is what stops the growth the design's
        # risk table claimed the container had measured.
        self.assertIn("pending", got)
        for name, size in got["pending"].items():
            with self.subTest(name=name):
                self.assertLessEqual(size, bench.MAX_PENDING)

    def test_the_handoff_is_a_write_and_a_read(self):
        got = bench.measure_handoff(rounds=10)
        self.assertEqual(got["rounds"], 10)
        self.assertGreater(got["us_per_round"], 0)
        self.assertTrue(got["read_back"])

    def test_a_handoff_that_cannot_be_read_back_is_reported_as_such(self):
        # The field has to be able to say no, or it is decoration: a bench
        # that always reported success would hide the one failure this
        # measurement exists to catch.
        with mock.patch.object(bench.handoff, "read_document",
                               lambda _root: None):
            self.assertFalse(bench.measure_handoff(rounds=3)["read_back"])

    def test_the_fresh_or_ignore_rule_is_checked_rather_than_timed(self):
        got = bench.measure_freshness()
        self.assertTrue(got["a_fresh_document_is_read"])
        self.assertTrue(got["a_stale_document_is_ignored"])
        self.assertTrue(got["a_document_from_the_future_is_ignored"])

    def test_a_broken_freshness_rule_is_reported_as_broken(self):
        # The same requirement as the handoff's: the bench has to be able
        # to report that the rule does **not** hold. A beacon that read
        # every document would be the defect this measurement is for.
        from software.c2.beacon import Beacon
        with mock.patch.object(Beacon, "_way_out_document",
                               lambda self: {"version": 1}):
            got = bench.measure_freshness()
        self.assertFalse(got["a_stale_document_is_ignored"])
        self.assertFalse(got["a_document_from_the_future_is_ignored"])

    def test_the_arithmetic_is_measured_and_its_crossings_reported(self):
        got = bench.measure_arithmetic(rounds=10)
        self.assertGreater(got["us_per_decision"], 0)
        # The ladder, as hours dark, read out of the beacon's own numbers
        # rather than typed here a second time.
        self.assertEqual(sorted(got["crossings"]),
                         ["way_out_borrow", "way_out_identity",
                          "way_out_radio"])
        self.assertLess(got["crossings"]["way_out_borrow"],
                        got["crossings"]["way_out_radio"])
        self.assertLess(got["crossings"]["way_out_radio"],
                        got["crossings"]["way_out_identity"])


class TestTheModelArm(unittest.TestCase):
    def test_with_no_model_named_it_says_it_was_not_run(self):
        got = bench.measure_model(name="")
        self.assertFalse(got["asked"])
        self.assertIn("no model", got["note"].lower())

    def test_a_bad_result_is_a_measurement_and_not_an_error(self):
        # The whole point of the arm: "the model answered something the
        # validator refused" is a finding, and it goes in the report.
        with mock.patch("software.scout.model.ask", lambda *a, **k: None):
            got = bench.measure_model(name="qwen2.5:0.5b")
        self.assertTrue(got["asked"])
        self.assertFalse(got["validated"])
        self.assertGreaterEqual(got["seconds"], 0)
        self.assertIn("optimistic", got["caveat"].lower())

    def test_it_can_be_asked_more_than_once_so_a_ratio_is_reportable(self):
        # The design's model numbers are a ratio -- "the validator
        # accepted nine of twelve" -- and the command written beside them
        # asked once, so a reader following the instructions got one
        # number and no ratio.
        answers = [{"verb": "gsocket", "chose": "model", "argument": "",
                    "p_success": None, "why": ""}, None,
                   {"verb": "portal", "chose": "model", "argument": "",
                    "p_success": None, "why": ""}, None]
        with mock.patch("software.scout.model.ask",
                        side_effect=list(answers)):
            got = bench.measure_model(name="qwen2.5:0.5b", asks=4)
        self.assertEqual(got["asks"], 4)
        self.assertEqual(got["accepted"], 2)
        self.assertEqual(got["verbs"], ["gsocket", "portal"])
        self.assertIn("2 of 4", got["note"])

    def test_an_accepted_answer_reports_what_the_validator_took(self):
        answer = {"verb": "gsocket", "chose": "model", "argument": "",
                  "p_success": 0.6, "why": "nothing answered"}
        with mock.patch("software.scout.model.ask", lambda *a, **k: answer):
            got = bench.measure_model(name="qwen2.5:0.5b")
        self.assertTrue(got["validated"])
        self.assertEqual(got["verb"], "gsocket")
        self.assertEqual(got["p_success"], 0.6)

    def test_a_model_that_cannot_be_reached_is_reported_not_raised(self):
        with mock.patch("software.scout.model.ask",
                        side_effect=OSError("connection refused")):
            got = bench.measure_model(name="qwen2.5:0.5b")
        self.assertTrue(got["asked"])
        self.assertFalse(got["validated"])
        self.assertIn("connection refused", got["note"])


class TestTheCommandLine(unittest.TestCase):
    def test_json_prints_the_report_and_exits_zero(self):
        from io import StringIO
        out = StringIO()
        with mock.patch("sys.stdout", out):
            self.assertEqual(bench.main(["--json", "--packets", "20",
                                         "--rounds", "20"]), 0)
        printed = json.loads(out.getvalue())
        self.assertIn("not_measurable", printed)

    def test_the_default_output_names_what_it_cannot_measure(self):
        from io import StringIO
        out = StringIO()
        with mock.patch("sys.stdout", out):
            bench.main(["--packets", "20", "--rounds", "20"])
        text = out.getvalue()
        self.assertIn("watts", text)
        self.assertIn("thermals", text)
        self.assertIn("optimistic", text.lower())


if __name__ == "__main__":
    unittest.main()

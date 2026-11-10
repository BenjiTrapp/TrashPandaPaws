#!/usr/bin/env python3
"""
Whether the delivered artifact carries any of the strings the published
detection content for the family this protocol derives from looks for --
and the documentation an operator reads about the feature.

**This is two tiers, and they prove different things.** Both are here
because only one of them can be had unconditionally: `yara-python` is not
in `software/requirements.txt` and that file may not grow.

1. **Real YARA, against the two checked-in rule files**, skipped when the
   engine is absent -- the `skipUnless(shutil.which(...))` precedent is
   `test_c2_hardening.py`'s, and the binary it looks for is `yara`. This
   is the real claim: the rules as published, compiled by the engine they
   were written for, do not match the artifact.
2. **An always-on marker assertion** over the rules' distinctive strings,
   run against the *generated artifact* rather than against `beacon.py`.
   This is the weaker claim and it is weaker in a way worth naming: it
   proves that **no listed marker survives generation**, not that no rule
   matches. A rule can match on a string nobody listed here, and a string
   can survive in a form a substring search does not see.

**A bare tier-1 pass would prove nothing, and two tests beside it are why
it does.** Both published rules are bounded by `filesize < 60KB` and the
generated artifact is roughly five times that, so neither rule can fire
on it whatever it contains — a "no match" has two independent causes and
only one of them is about our bytes. So:

* `test_the_checked_in_rules_still_match_what_they_were_written_for`
  synthesises a small file out of the marker list and requires both rules
  to match it. That rules out the other explanation for silence: a rule
  file that compiled to nothing, or a missing engine.
* `test_the_rules_do_not_match_even_without_their_filesize_bound` strips
  the `filesize` clause at run time, into a temporary directory, and
  scans the artifact again. **This is the strongest claim in this file.**
  It passes, which means the artifact escapes the published rules on
  their *strings* and not merely by being too large to be looked at —
  and it is this test, not tier 2, that carries the claim about the
  artifact's bytes. Tier 2 is the guard that still runs when the engine
  is absent.

`docs/TUNNEL.md` says the same thing in the same order.

**The marker list is the rules' distinctive strings, not all of them.**
Four of the rule's exception names -- `ConnectionResetError`,
`ConnectionAbortedError`, `ConnectionRefusedError` and
`ConnectionClosedError` -- are names Python itself defines or that any
socket module might, and the rule needs three of *those* plus three class
names before it fires. A build that merely catches one is not at risk, so
listing them here would make this test fail on an innocent `except`
clause. Tier 1 covers the full string set regardless.

**Three names in the list are ours to keep out, not the rules'.**
`VIPERTUNNEL`, `InfoGuard` and the write-up's title are not strings in
either rule; they are what *names* the family and the analysis that burned
it. The generator ships comments verbatim into the delivered artifact, so a
section comment naming them handed an analyst the artifact's own
attribution and a citation for the write-up. The prose moved to
`software/c2/tunnel/protocol.py`, which is server-side and never
delivered, and to `docs/TUNNEL.md`; these three entries are what stops a
future paste from bringing it back.

**This is not the leakage walk in `test_tunnel_persistence.py`, and the
two lists do not overlap.** That one walks every shipped file in the
repository for two *other* literals from the same write-up -- the burned
autorun name that used to be in every deployment, and the layout directory
the write-up names. This one walks nothing: it reads one artifact and one
source file, and its list is the published rules' strings plus the three
provenance names above.
"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from software.tests.test_tunnel_config import _GeneratorCase, _innermost

_REPO = Path(__file__).resolve().parents[2]
_RULE_DIR = Path(__file__).resolve().parent / "data"
_RULES = ("vipertunnel.yar", "vipertunnel_typos.yar")

_BEACON = _REPO / "software" / "c2" / "beacon.py"
_TUNNEL_DOC = _REPO / "docs" / "TUNNEL.md"
_LISTENER_DOC = _REPO / "docs" / "LISTENERS.md"
_README = _REPO / "README.md"

# The distinctive strings the two published rules look for, as data. From
# the design's "Not matching the rules we came from"; see this module's
# docstring for which of the rules' strings are deliberately not here and
# why.
_RULE_STRINGS = (
    # Class names.
    "class Wire(",
    "class Relay(",
    "class Commander(",
    "class ControllerCommandConnection",
    "class MySocket",
    "class MyServiceSocket",
    "class Handler",
    # Custom exception names -- the four the original invented.
    "ConnectionTimeoutOccuredError",
    "BadLengthData",
    "CloseException",
    "ExitException",
    # Logic-specific strings and unique variables.
    "main_flag_to_close",
    "TIMEOUT_FOR_SOCKET_OPERATION",
    "self.must_equal",
    "def _bridge(self):",
    "socket.socket = Wire",
    # The hardcoded credentials.
    "AnyLogin",
    "AnyPassword",
    # The original's own typos.
    "allow_no_verifing",
    "__setatrr__",
    "deamon",
)

# What names the family and the analysis. Not rule strings -- see the
# module docstring.
_PROVENANCE_NAMES = (
    "VIPERTUNNEL",
    "InfoGuard",
    "Slithering Through the Noise",
)

_MARKERS = _RULE_STRINGS + _PROVENANCE_NAMES

# Phrasings that frame this code as a port of something else, rather than
# naming it. The three provenance names above are not the only way to tell
# an analyst the artifact is derived from a published tool: "the original",
# "the inherited keep-alive" and "the protocol this derives from" all say
# it without naming anything, and all three shipped in `beacon.py` until
# this was written.
#
# **This exists because a case-sensitive grep is what let three of them
# through.** A one-time sweep for `the original` missed `The original
# dropped it` on a capital letter, and two of the three survivors were
# exception message strings -- which ship in the artifact as data as well
# as text. So the sweep is a test, it is case-insensitive, and it runs on
# every commit.
#
# Deliberately narrow. `beacon.py` legitimately says "derive" twenty-odd
# times (X25519 and `EVP_PKEY_derive`), "derived from" about generated
# names, and "published" about the *Noise specification's* test vectors.
# None of that frames this code against another tool, so the patterns
# match the comparative construction and not the bare words.
_LINEAGE_PATTERNS = (
    r"\bthe original\b",            # "The original dropped it"
    r"\binherit",                   # "the inherited keep-alive"
    r"this\s+(?:\w+\s+){0,3}deriv",  # "the protocol this derives from"
    r"published\s+original",        # "The published original did a bare"
)


def _has_yara():
    """The engine, as a binary on PATH, following the `node` precedent."""
    return shutil.which("yara") is not None


# Named so that a green run is self-describing. `skipped=4` beside a
# reason that only states the cause reads like any other skip; this says
# which claim was not made, because the whole point of tier 1 is that it
# is the real one.
_NO_YARA = ("yara binary not on PATH: tier 1, the real claim -- that the "
            "published rules do not match the artifact -- was NOT "
            "verified. Only the tier-2 marker assertion ran.")


def _scan(rules, target):
    """The rule names that matched `target`, via the `yara` binary."""
    result = subprocess.run(
        [shutil.which("yara"), "--no-warnings", str(rules), str(target)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise AssertionError(
            "yara refused %s: %s"
            % (Path(rules).name,
               result.stderr.decode("utf-8", "replace").strip()))
    return [line.split()[0]
            for line in result.stdout.decode("utf-8", "replace").splitlines()
            if line.strip()]


def _flat(path):
    """One whitespace-normalised lowercase line, for prose assertions."""
    return " ".join(path.read_text(encoding="utf-8").split()).lower()


def _flattened_with_lines(path):
    """`(one normalised string, [(offset, line number, raw line)])`.

    Prose wraps, so a comparative phrase is routinely split across a
    line break. The site this was written for had `zero. The` ending one
    comment line and `original dropped it` starting the next, so a
    line-by-line search could not see "the original" at all -- which is
    the second way a sweep for this misses something, after case. Lines
    are flattened before matching for the same reason `test_docs.py`
    normalises before asserting on prose: the search is about the
    phrase, not the column it broke at.

    A leading `#` is stripped so a comment reads as its sentence.
    Strings are left exactly as they are, because an exception message
    ships in the artifact as data as well as text and is the thing most
    worth catching.
    """
    chunks, index, offset = [], [], 0
    for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if text.startswith("#"):
            text = text[1:].strip()
        index.append((offset, number, line.strip()))
        chunks.append(text)
        offset += len(text) + 1
    return " ".join(chunks), index


def _line_at(index, position):
    """The `(number, raw line)` whose flattened text covers `position`."""
    found = index[0]
    for entry in index:
        if entry[0] > position:
            break
        found = entry
    return found[1], found[2]


def _uncommented(text):
    """`text` with YARA `//` comments stripped.

    The header comment records the clause that was removed, so it names
    `vt.metadata.file_type` on purpose. An assertion that the module is
    gone has to read the rule and not the note about the rule.
    """
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


class _ArtifactCase(_GeneratorCase):
    """One generated build, in both the forms it exists in.

    `_GeneratorCase` is reused rather than copied so there is one
    unwrapper for the delivered artifact's shape in this suite, and so a
    change to `_obfuscate_layer` fails loudly in one place.
    """

    def artifact(self, route="gen"):
        """`(delivered, expanded)` for one build with a tunnel baked in.

        `delivered` is the text inside `python3 -c "..."`, which is what
        actually lands on a host; `expanded` is the source it decodes to,
        which is what runs and what an analyst recovers. The first is
        base64 of a deflate stream, so no marker could appear in it
        literally -- it is checked anyway, because a marker in the
        *wrapper* would be a real leak and costs nothing to rule out.
        """
        response = getattr(self, "post_" + route)(self.asked_for())
        self.assertEqual(response.status_code, 200, response.data[:400])
        body = response.get_json()
        if route == "gen":
            prefix = 'python3 -c "'
            one = body["oneliner_unix"]
            self.assertTrue(one.startswith(prefix) and one.endswith('"'),
                            one[:80])
            delivered = one[len(prefix):-1]
        else:
            self.assertIsNotNone(self._uploaded,
                                 "the gist route uploaded nothing")
            delivered = self._uploaded
        expanded = _innermost(delivered)
        self.assertIn("class TunnelEndpoint", expanded,
                      "the artifact did not unwrap to the beacon's source, "
                      "so nothing below read what ships")
        return delivered, expanded


class TestTheArtifactCarriesNoPublishedMarker(_ArtifactCase):
    """Tier 2: the always-on claim, over the generated artifact."""

    def test_generated_artifact_contains_no_marker_from_the_published_rules(
            self):
        # Both generator routes, not one. They assemble their own
        # `gen_cfg` between them, and a comment or a generated value that
        # reached only one of them is this repository's most frequent
        # defect -- `test_tunnel_config.py`'s docstring says so.
        offenders = []
        for route in ("gen", "gist"):
            delivered, expanded = self.artifact(route)
            for form, text in (("the delivered one-liner", delivered),
                               ("the source it expands to", expanded)):
                for marker in _MARKERS:
                    if marker in text:
                        offenders.append("%s %s: %r" % (route, form, marker))
        self.assertEqual(
            offenders, [],
            "the generated artifact carries a string the published "
            "detection content for the family this derives from looks "
            "for, or a name that identifies that family: %s"
            % "; ".join(offenders))

    def test_beacon_source_contains_no_marker_from_the_published_rules(self):
        # The artifact is this file plus a config block, so a marker here
        # is a marker there. Asserted separately because this is the one
        # a developer edits and the one a careless paste lands in.
        text = _BEACON.read_text(encoding="utf-8")
        offenders = [marker for marker in _MARKERS if marker in text]
        self.assertEqual(
            offenders, [],
            "software/c2/beacon.py carries %s, and `api_beacon_gen` ships "
            "this file's comments verbatim into every build"
            % ", ".join(repr(name) for name in offenders))

    def test_beacon_source_frames_this_code_against_no_other_tool(self):
        """No comparative framing in the one file that is delivered.

        The marker list above catches the three *names*. This catches
        saying the same thing without them -- "the original", "the
        inherited keep-alive", "the protocol this derives from" -- which
        tells a reader of the artifact it is a port of a published tool
        just as plainly.

        Scoped to `beacon.py` on purpose, and not to the tree. The
        lineage belongs in `software/c2/tunnel/protocol.py`,
        `tunnel/server.py`, `docs/TUNNEL.md` and the protocol tests,
        none of which is ever delivered to a host. This file is.
        """
        offenders = []
        text, index = _flattened_with_lines(_BEACON)
        for pattern in _LINEAGE_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                number, line = _line_at(index, match.start())
                offenders.append("beacon.py:%d: %r in %r"
                                 % (number, match.group(0), line))
        offenders.sort()
        self.assertEqual(
            offenders, [],
            "beacon.py frames itself against another tool, and every "
            "comment and message string in it ships verbatim to a host. "
            "State the property of this code instead, and put the "
            "comparison in software/c2/tunnel/protocol.py:\n%s"
            % "\n".join(offenders))

    def test_the_artifact_is_past_the_filesize_bound_both_rules_carry(self):
        # Stated as a number rather than as prose, because it is the
        # second independent reason a bare tier-1 pass proves nothing,
        # and `docs/TUNNEL.md` has to keep saying so. Deliberately *not*
        # in the yara-gated class below: it needs no engine, and a run
        # without one should still record the fact that makes the skip
        # matter.
        _delivered, expanded = self.artifact()
        self.assertGreater(len(expanded.encode("utf-8")), 60 * 1024)


class TestTheCheckedInRules(unittest.TestCase):
    """The checked-in copies, and the marker list measured against them."""

    def test_the_marker_list_holds_the_three_names_that_identify_us(self):
        # A regression guard on the list itself: these three left
        # `beacon.py` in this task, and the list is the only thing that
        # stops them coming back.
        for name in ("VIPERTUNNEL", "InfoGuard", "Slithering Through the "
                                                 "Noise"):
            self.assertIn(name, _MARKERS, name)

    def test_the_checked_in_rules_declare_the_vt_clause_was_removed(self):
        for name in _RULES:
            path = _RULE_DIR / name
            with self.subTest(rule=name):
                self.assertTrue(path.is_file(), "%s is missing" % name)
                text = path.read_text(encoding="utf-8")

                # Split at the rule declaration, which is at the start of
                # a line -- not at the first "rule ", which the header
                # comment itself contains.
                header = re.split(r"(?m)^rule\s", text, maxsplit=1)[0]
                flat = " ".join(header.split()).lower()
                self.assertIn("vt.metadata.file_type", header,
                              "the header does not say which clause was "
                              "removed, so this copy could be mistaken "
                              "for the original")
                for claim in ("removed", "slithering through the noise"):
                    self.assertIn(claim, flat,
                                  "the header does not record %r" % claim)

                # The rule itself: the module is gone, and the parts that
                # make it a rule are not.
                body = _uncommented(text)
                for module in ("vt.metadata", "vt.FileType", "import \"vt\""):
                    self.assertNotIn(
                        module, body,
                        "%s still evaluates the vt module, which plain "
                        "YARA cannot do" % name)
                self.assertIn("filesize < 60KB", body,
                              "the filesize bound was dropped, which is a "
                              "change to the rule and not to the module it "
                              "could not evaluate")
                self.assertIn("condition:", body)
                self.assertRegex(body, r"\d+ of \(\$\w+\*\)",
                                 "the counting logic was dropped")

    def test_the_rules_are_not_edited_beyond_the_vt_clause(self):
        # Every marker this suite asserts the absence of has to be a
        # string one of these two files actually looks for, or the two
        # tiers are measuring different things.
        text = "".join((_RULE_DIR / name).read_text(encoding="utf-8")
                       for name in _RULES)
        missing = [marker for marker in _RULE_STRINGS if marker not in text]
        self.assertEqual(missing, [],
                         "the marker list names strings the checked-in "
                         "rules do not look for: %s" % missing)


@unittest.skipUnless(_has_yara(), _NO_YARA)
class TestTheRulesDoNotMatch(_ArtifactCase):
    """Tier 1: the real claim, when the engine is here to make it.

    One generator route here, unlike tier 2. The two routes differ in how
    they *deliver* the artifact and not in the source it expands to, and
    this tier scans the expanded source -- so a second route would scan
    the same bytes through a second `yara` process. Tier 2 drives both
    because it also reads the delivered form, which is where they differ.
    """

    def test_published_rules_do_not_match_the_generated_artifact(self):
        _delivered, expanded = self.artifact()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.py"
            target.write_text(expanded, encoding="utf-8")
            for name in _RULES:
                with self.subTest(rule=name):
                    matched = _scan(_RULE_DIR / name, target)
                    self.assertEqual(
                        matched, [],
                        "%s matches the generated artifact" % name)

    def test_the_checked_in_rules_still_match_what_they_were_written_for(self):
        # The positive control, and the reason the negative above is worth
        # reading. Both rules are bounded by `filesize < 60KB` and the
        # artifact is far larger, so "no match" would also be the answer
        # from a rule file that compiled to nothing. This synthesises a
        # small file out of the marker list and requires both rules to
        # fire on it.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "control.py"
            target.write_text("\n".join(_RULE_STRINGS) + "\n",
                              encoding="utf-8")
            self.assertLess(target.stat().st_size, 60 * 1024)
            for name in _RULES:
                with self.subTest(rule=name):
                    matched = _scan(_RULE_DIR / name, target)
                    self.assertNotEqual(
                        matched, [],
                        "%s fires on nothing, so its companion test "
                        "proves nothing either" % name)

    def test_the_rules_do_not_match_even_without_their_filesize_bound(self):
        """The same scan with the second reason it cannot fail removed.

        `filesize < 60KB` means the two tests above would both answer "no
        match" on an artifact that *did* carry a string, so neither of
        them alone separates "our bytes are clean" from "the artifact is
        too big to be looked at". This strips that one clause -- at run
        time, into a temporary directory, so the checked-in copies stay
        as published bar the `vt` edit their headers record -- and asks
        again. A match here would be a real leak that the published rule
        would miss only by luck of size.
        """
        _delivered, expanded = self.artifact()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.py"
            target.write_text(expanded, encoding="utf-8")
            for name in _RULES:
                with self.subTest(rule=name):
                    text = (_RULE_DIR / name).read_text(encoding="utf-8")
                    relaxed = text.replace("filesize < 60KB and", "")
                    self.assertNotIn("filesize", _uncommented(relaxed),
                                     "the bound was not the shape this "
                                     "expected, so nothing was relaxed")
                    unbounded = Path(tmp) / name
                    unbounded.write_text(relaxed, encoding="utf-8")
                    self.assertEqual(
                        _scan(unbounded, target), [],
                        "%s matches the generated artifact once its "
                        "filesize bound is lifted, so the artifact does "
                        "carry its strings and escapes the published "
                        "rule only by being large" % name)


class TestTheTunnelDocumentation(unittest.TestCase):
    """`docs/TUNNEL.md`: the facts an operator cannot get anywhere else.

    Every claim here was decided during the build and is recorded nowhere
    an operator reads. Asserted as claims rather than as sentences: the
    prose is free, the facts are not.
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = _flat(_TUNNEL_DOC)

    def present(self, needle, what):
        self.assertTrue(" ".join(needle.split()).lower() in self.doc,
                        "%s: %r is not in docs/TUNNEL.md" % (what, needle))

    def test_tunnel_doc_states_the_key_bearing_difference_from_a_listener(
            self):
        self.present("the tunnel server holds key material and a listener "
                     "does not",
                     "the property docs/LISTENERS.md leads with is inverted "
                     "here and the document has to say so")
        self.present("LISTENERS.md", "the document it contradicts")

    def test_the_listener_guide_points_at_the_exception(self):
        # A reader of that document must not be left with a guarantee
        # that has an exception they never see, so the pointer goes in
        # the section that states the guarantee -- not in a footer.
        text = _LISTENER_DOC.read_text(encoding="utf-8")
        section = text.split("## The one property everything else rests on",
                             1)
        self.assertEqual(len(section), 2,
                         "docs/LISTENERS.md no longer leads with the "
                         "property this is an exception to")
        body = section[1].split("\n## ", 1)[0]
        self.assertIn("TUNNEL.md", body,
                      "the section that states the guarantee does not "
                      "point at the one thing that inverts it")

    def test_the_doc_says_which_tier_of_the_test_proves_what(self):
        self.present("filesize < 60KB",
                     "the bound that stops both rules firing on an "
                     "artifact this size")
        self.present("not that no rule matches",
                     "the limit of the always-on tier")
        for claim in ("yara", "skipped"):
            self.present(claim, "how tier 1 behaves without the engine")

    def test_the_doc_describes_both_objects_and_both_stops(self):
        self.present("drops every endpoint at once", "the server's stop")
        self.present("next check-in", "when an endpoint's stop takes effect")
        self.present("pending", "how an endpoint's stop is shown")

    def test_the_doc_states_the_port_is_per_identity_and_authenticates(self):
        self.present("one fixed SOCKS port per identity", "the port")
        self.present("loopback is not isolation from other local users",
                     "why the port authenticates")
        self.present("RFC 1929", "what it authenticates with")

    def test_the_doc_states_why_a_slow_crypto_path_refuses_to_start(self):
        self.present("50-200 KB/s", "the measured throughput")
        self.present("refuses to start", "what the endpoint does about it")
        self.present("network fault", "what it would be mistaken for")

    def test_the_doc_says_the_row_names_both_crypto_paths(self):
        # Two tasks called a field `crypto` and meant different
        # processes. The endpoint's path never leaves the target unless
        # the HELLO carries it, and the row an operator reads in the one
        # case the display exists for -- a build with `allow_slow_crypto`
        # set because the target has no libcrypto -- used to report the
        # team server's `openssl`.
        self.present("endpoint_crypto", "the implant's own cipher path")
        self.present("server_crypto", "this process's")
        self.present("decrypts and re-encrypts every relayed byte",
                     "why the server's path matters to throughput too")

    def test_the_doc_separates_the_stable_port_from_the_rotating_password(
            self):
        # They sat one below the other -- "stable across restarts" about
        # the port, "held in memory, never written to disk" about the
        # password -- and read as one line about one credential.
        # `_Fronts.reconcile` mints a new password per identity on every
        # tunnel-server start, so after a restart the port is the same
        # and the password is not.
        self.present("the port is stable across restarts and the password "
                     "is not",
                     "the two facts, said apart")
        self.present("re-read the password off the row",
                     "what to do after a restart")

    def test_the_doc_makes_persist_a_step_in_the_staging_sequence(self):
        # A staged host's only Python is the one the stager brought,
        # under a generated `base_dir`, so "staged, not persisted, then
        # rebooted" leaves nothing running and nothing to find.
        self.present("task `persist` to the agent as soon as it checks in",
                     "the step, in the sequence rather than in a note")
        self.present("leaves nothing running",
                     "what staging without it costs")

    def test_the_doc_shows_a_request_that_asks_for_a_tunnel_and_drops(self):
        # `runBeaconGen` posts neither key and renders neither stager, so
        # the only way to either today is a request by hand. The
        # documentation told the operator to "ask for a tunnel in the
        # generation request" and never showed one.
        self.present("api/server/beacon-gen", "the route")
        self.present("the Beacon Gen form cannot do yet",
                     "that the panel cannot ask for this")
        for key in ('"tunnel"', '"drops"', '"enabled": true',
                    "stager_nix", "stager_win"):
            self.present(key, "part of the request or its answer")
        for field in ("base_dir", "payload_name", "gate"):
            self.present(field, "a response field the bundle builder needs")

    def test_the_doc_says_where_the_crypto_override_actually_lives(self):
        # The one section an operator reaches in a failure state. A
        # generated build carries `allow_slow_crypto` baked in and reads
        # no config file, so "edit raccoon.yaml" is the wrong remedy for
        # the common artifact -- and the document held both halves of
        # that 130 lines apart without connecting them.
        self.present("regenerate the build",
                     "what a generated build's operator must actually do")
        self.present("generation time",
                     "when the field is chosen for a generated build")
        self.present("Editing `raccoon.yaml` on the target changes "
                     "nothing",
                     "the remedy that does not work, said plainly")
        self.present("raccoon-tunnel.service",
                     "which kind of endpoint the YAML block is for")

    def test_the_doc_assembles_the_happy_path_into_one_sequence(self):
        # Four steps that were each documented and never ordered.
        for claim in ("the happy path", "tunnel start", "proxychains"):
            self.present(claim, "the ordered sequence")

    def test_the_doc_states_the_drop_list_and_the_mandatory_hash(self):
        self.present("sha256", "what pins a drop")
        self.present("remote code execution in our own implant",
                     "why the hash has no override")

    def test_the_doc_records_that_no_tool_assembles_a_posix_bundle(self):
        self.present("no tool assembles a POSIX bundle",
                     "the gap between the two stagers")
        self.present("probe-and-delegate", "what the POSIX stager is for")

    def test_the_doc_records_that_the_stager_installs_no_persistence(self):
        self.present("the stager installs no persistence",
                     "an earlier design step said it would")
        self.present("explicit operator action",
                     "what persistence is instead")


class TestTheReadme(unittest.TestCase):
    def test_readme_distinguishes_the_pivot_map_from_the_pivot(self):
        flat = _flat(_README)
        # The picture keeps its name, and now says it is a picture.
        self.assertIn("pivot map", flat, "the README lost the pivot map")
        # `assertRegex` would print the whole README on failure.
        self.assertTrue(
            re.search(r"pivot map[^.|]{0,80}visualisation of scan results",
                      flat),
            "the README advertises a pivot map without saying it is a "
            "visualisation, so a reader cannot tell it from the tunnel")
        # And the actual pivot is named, with a different name.
        self.assertIn("reverse socks tunnel", flat,
                      "the README never names the thing that does pivot")
        self.assertIn("docs/tunnel.md", flat,
                      "the README does not link docs/TUNNEL.md")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The documentation's factual tables, checked against the code.

docs/AGENT.md states numbers: capability tiers, risk profile values, the
forced scan flags, the eight actions that are never permitted, the eleven
that are gated. Those are the parts a reader will rely on and the parts
that go stale silently -- a renamed action or a changed default leaves prose
that is confidently wrong, which is worse than prose that is vague.

So this does for the documentation what test_c2_agent_gui does for the GUI's
JavaScript tables: compares them to the source of truth, and fails when they
drift. It asserts that every key and every number is *present*, not that the
surrounding sentences are unchanged -- the prose is free, the facts are not.
"""

import argparse
import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from software.agent import config, prompts
from software.agent.llm import failover
from software.agent.store import queries  # noqa: E402
from software.agent import safety  # noqa: E402
from software.agent.executor import server_tool  # noqa: E402
from software.agent.llm import provider  # noqa: E402
from software.c2 import server as c2_server  # noqa: E402
from software.c2.sliver import SliverManager  # noqa: E402

AGENT_DOC = REPO / "docs" / "AGENT.md"
DEMO_DOC = REPO / "docs" / "C2_DEMO.md"
REDIRECTOR_DOC = REPO / "docs" / "REDIRECTOR.md"
README = REPO / "README.md"


def _rows_under(text, heading):
    """Markdown table rows in the section introduced by `heading`."""
    body = text.split(heading, 1)
    if len(body) < 2:
        raise AssertionError("no section %r" % heading)
    out = []
    for line in body[1].splitlines():
        # Any heading ends the section, not only a level-two one: a "###"
        # below it would otherwise pull the next table's rows in.
        if line.startswith("#") and out:
            break
        if line.startswith("|") and not set(line) <= set("|- :"):
            out.append(line)
    return out


class _DocCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = AGENT_DOC.read_text()

    def present(self, needle, what):
        """assertIn without printing the haystack, and across line wraps.

        Prose wraps, so a phrase that reads as one sentence is two lines in
        the file. Comparing against a whitespace-normalised copy keeps the
        test about the sentence rather than about the column it broke at.
        """
        # Case-insensitive as well: the same sentence is capitalised at the
        # start of a line and lowercase mid-sentence, and the test is about
        # the claim, not about where it happened to land.
        flat = " ".join(self.doc.split()).lower()
        self.assertTrue(" ".join(needle.split()).lower() in flat,
                        "%s: %r is not in AGENT.md" % (what, needle))

    def states_number(self, text, what):
        """Like present(), but a number must stand on its own.

        `present("2 minutes")` passed against "22 minutes of probing"
        further down the page -- an accidental substring match, so the
        cooldown figure was never actually checked. Numbers get word
        boundaries.
        """
        flat = " ".join(self.doc.split())
        self.assertRegex(flat, r"(?<![\d.])" + re.escape(text),
                         "%s: %r is not stated in AGENT.md" % (what, text))

    def absent(self, needle, what):
        self.assertTrue(needle not in self.doc, "%s: %r should not be in "
                        "AGENT.md" % (what, needle))


class TestTheCapabilityTiersAreStatedCorrectly(_DocCase):
    def test_every_tier_is_named(self):
        for tier in provider.TIER_LIMITS:
            self.present("`%s`" % tier, "capability tier")

    def test_each_tiers_turn_limits_appear_in_its_row(self):
        for tier, limits in provider.TIER_LIMITS.items():
            row = self._row_for(tier)
            for field in ("orchestrator_turns", "executor_turns",
                          "truncate_chars", "max_phase"):
                self.assertIn(str(limits[field]), row,
                              "%s: %s" % (tier, field))

    def _row_for(self, tier):
        for line in self.doc.splitlines():
            if line.startswith("|") and ("`%s`" % tier) in line:
                return line
        self.fail("no table row for tier %r" % tier)


class TestThePhasesAreStatedCorrectly(_DocCase):
    def test_every_phase_name_appears(self):
        for number, name in prompts.PHASE_NAMES.items():
            self.present(name, "phase %d" % number)

    def test_the_phase_table_uses_no_invented_name(self):
        # The GUI once called phase 3 "Credential access" and phase 4
        # "Lateral movement". Neither is a phase of this agent. The prose
        # may mention them -- the page explains that mistake on purpose --
        # but the table must not, which is why this reads the table.
        table = "\n".join(_rows_under(self.doc, "## Phases"))
        for ghost in ("Credential access", "Lateral movement"):
            self.assertNotIn(ghost, table, ghost)


class TestTheRiskProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_and_every_number_appears(self):
        rows = _rows_under(self.doc, "## Risk profiles")
        for name, values in config.RISK_PROFILES.items():
            row = next((r for r in rows
                        if r.split("|")[1].strip().strip("`") == name), None)
            self.assertIsNotNone(row, "no row for risk profile %r" % name)
            for field, value in values.items():
                # Written for a reader: 20.0 appears as "+20", -5.0 as a
                # minus sign, 0.25 as "0.25". Compare on the number.
                shown = ("%g" % value)
                candidates = {shown, "+" + shown, shown.replace("-", "\u2212")}
                self.assertTrue(any(c in row for c in candidates),
                                "%s/%s: %s not in its row" % (name, field, shown))


class TestTheOpsecProfilesAreStatedCorrectly(_DocCase):
    def test_every_profile_is_named(self):
        for name in config.OPSEC_PROFILES:
            self.present("`%s`" % name, "opsec profile")

    def test_the_yolo_promise_is_written_down(self):
        # The one sentence in this file that is load-bearing: the name
        # invites "safety off", and nine tests exist to refuse that reading.
        self.present("lifts the scan rate limits and nothing else",
                     "what yolo does")
        self.present("tier-1 actions stay blocked", "what yolo does not")


class TestTheGateListsMatchTheRiskTable(_DocCase):
    def _keys(self, tier):
        return {k for k, row in safety.RISK_TABLE.items() if row.tier == tier}

    def test_every_never_permitted_action_is_listed(self):
        for key in self._keys(safety.TIER_HARD):
            self.present("`%s`" % key, "tier-1 action")

    def test_every_gated_action_is_listed(self):
        for key in self._keys(safety.TIER_KNOCK):
            self.present("`%s`" % key, "gated action")

    def test_the_tier_one_table_has_exactly_the_tier_one_rows(self):
        # Counting the table, not parsing the prose: the sentence may be
        # rewritten, the table may not gain or lose a row silently.
        rows = _rows_under(self.doc, "### Never permitted, in any mode")
        # rows[0] is the header; the separator line is already filtered out.
        keys = {r.split("|")[1].strip().strip("`") for r in rows[1:]}
        self.assertEqual(keys, self._keys(safety.TIER_HARD))

    def test_a_tier_one_action_is_never_described_as_approvable(self):
        # The distinction the whole page rests on.
        self.present("cannot be approved", "the tier-1 promise")


class TestTheScanLimitsAreStatedCorrectly(_DocCase):
    def test_the_forced_flags_are_read_back_from_the_limiter(self):
        for program in ("nmap", "masscan", "netdiscover"):
            tokens = safety.enforce_scan_limits(
                "%s 192.0.2.1" % program).split()
            self.present(" ".join(tokens[1:-1]), "forced flags for " + program)

    def test_the_port_cap_and_the_nmap_timeout_are_the_real_numbers(self):
        self.present(str(safety.SCAN_TOP_PORTS), "the port cap")
        self.present(str(server_tool._TOOL_TIMEOUTS["nmap"]), "nmap's timeout")


class TestTheProvidersAreStatedCorrectly(_DocCase):
    def test_every_provider_the_code_accepts_is_documented(self):
        for name in provider._PROVIDERS:
            self.present("`%s`" % name, "provider")

    def test_the_shipped_config_lists_them_too(self):
        text = (REPO / "configs" / "raccoon.yaml").read_text()
        for name in provider._PROVIDERS:
            self.assertIn(name, text, name)


class TestTheUnattendedDefaultsAreStatedCorrectly(_DocCase):
    def test_every_behaviour_is_described(self):
        for name in config._UNATTENDED:
            self.present("`%s`" % name, "unattended behaviour")

    def test_the_asymmetric_default_is_explained(self):
        # Two defaults for one field is surprising, so the page has to say
        # which is which rather than leave a reader to find out.
        self.present("supervised \u2192 `pause`", "the supervised default")
        self.present("Full Automated \u2192\n`decide`",
                     "the Full Automated default")


class TestTheBudgetDefaultsAreStatedCorrectly(_DocCase):
    def test_the_numbers_match_the_form(self):
        form = config.CampaignConfig.from_form(
            {"beacons": ["b"], "scope_allow": ["10.0.0.0/24"],
             "mode": "auto"}, tier="full")
        for value in (form.max_runtime_seconds, form.max_tokens_total,
                      form.campaign_interval, form.restore_interval):
            number = int(value)
            # 500000 is written 500 000 for a reader.
            spaced = "{:,}".format(number).replace(",", " ")
            self.assertTrue(str(number) in self.doc or spaced in self.doc,
                            number)

    def test_the_approval_timeout_default_is_stated(self):
        self.present(str(int(config.AgentConfig().approval_timeout)),
                     "the approval timeout default")


class TestTheFiguresExist(unittest.TestCase):
    """A broken image is a broken promise in a document about evidence."""

    def _links(self, text):
        return re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)

    def test_every_figure_in_the_agent_page_resolves(self):
        for link in self._links(AGENT_DOC.read_text()):
            self.assertTrue((AGENT_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_demo_page_resolves(self):
        for link in self._links(DEMO_DOC.read_text()):
            self.assertTrue((DEMO_DOC.parent / link).exists(), link)

    def test_every_figure_in_the_readme_resolves(self):
        # The front page, where a broken image is seen first. It uses HTML
        # <img> tags as well as markdown links.
        import re as _re
        text = README.read_text()
        links = self._links(text) + _re.findall(r'<img src="([^"]+)"', text)
        for link in links:
            if link.startswith(("http://", "https://")):
                continue
            self.assertTrue((README.parent / link).exists(), link)

    def test_the_agent_page_shows_at_least_the_knock_card(self):
        # The one figure the design's own mockup is about.
        links = self._links(AGENT_DOC.read_text())
        self.assertTrue(any("knock" in link for link in links), links)


class TestTheDocumentationIsReachable(unittest.TestCase):
    def test_the_readme_points_at_the_agent_page(self):
        self.assertTrue("docs/AGENT.md" in README.read_text(),
                        "README.md does not link docs/AGENT.md")

    def test_the_demo_page_points_at_the_agent_page(self):
        self.assertTrue("AGENT.md" in DEMO_DOC.read_text(),
                        "C2_DEMO.md does not link AGENT.md")

    def test_the_agent_page_points_back_at_the_demo(self):
        self.assertTrue("C2_DEMO.md" in AGENT_DOC.read_text(),
                        "AGENT.md does not link C2_DEMO.md")


class TestTheStatusQuoPromiseIsStated(_DocCase):
    def test_the_page_says_the_c2_runs_without_a_model(self):
        # The promise an evaluator checks first, and the one the whole
        # separate-service architecture exists to keep.
        self.present("run exactly as they do today", "the status-quo promise")
        self.present("test_status_quo.py", "where to verify it")



class TestTheProofBasesAreStatedCorrectly(_DocCase):
    """Three values and no free text -- so all three have to be documented,
    and the documentation must not invent a fourth."""

    def test_every_basis_the_code_accepts_is_documented(self):
        for basis in queries.PROOF_BASES:
            self.present(basis, "proof basis")

    def _table(self):
        """The proof-basis table's rows, by its header."""
        after = self.doc.split("| `proof_basis` | means |", 1)
        self.assertEqual(len(after), 2, "the proof-basis table is gone")
        rows = []
        # lstrip: the text after the header starts with the newline that
        # ended it, so the first splitlines() element is empty and the
        # loop used to break before reading a single row.
        for line in after[1].lstrip("\n").splitlines():
            if not line.startswith("|"):
                break
            rows.append(line)
        return [r for r in rows if "---" not in r]

    def test_the_table_lists_exactly_the_three(self):
        # Scoped to the table, not the page: "inferred" also appears in the
        # report example further down, so a table row renamed to `guessed`
        # was invisible to a page-wide search for each known value.
        listed = []
        for row in self._table():
            found = re.findall(r"`([a-z-]+)`", row)
            listed.extend(found)
        self.assertEqual(sorted(listed), sorted(queries.PROOF_BASES),
                         "the table lists %s; the code accepts %s"
                         % (sorted(listed), sorted(queries.PROOF_BASES)))


class TestTheFallbackFieldsAreStatedCorrectly(_DocCase):
    """A config example that names a field the parser refuses is worse than
    no example: it is followed, and then the agent will not start."""

    def test_every_field_an_entry_takes_is_documented(self):
        for field in config._FALLBACK_FIELDS:
            self.present(field, "fallback field")

    def test_the_example_uses_no_field_the_parser_refuses(self):
        block = self.doc.split("fallbacks:", 1)[1].split("```", 1)[0]
        for key in re.findall(r"^\s*[-\s]*([a-z_]+):", block, re.M):
            self.assertIn(key, config._FALLBACK_FIELDS,
                          "the example sets %r, which an entry does not take"
                          % key)

    def test_the_literal_key_refusal_is_written_down(self):
        # The one thing someone will try, and the reason it is refused.
        self.present("api_key", "the refused literal")
        self.present("under git", "why a literal key is refused")

    def test_the_trip_and_cooldown_are_the_real_numbers(self):
        self.states_number("%d minutes"
                           % round(failover.DEFAULT_COOLDOWN / 60), "cooldown")
        self.present("twice in a row", "the trip threshold in words")
        self.assertEqual(failover.DEFAULT_TRIP_AFTER, 2,
                         "AGENT.md says 'twice in a row'; the code no longer "
                         "agrees")


class TestTheDeadlineThresholdsAreStatedCorrectly(_DocCase):
    def test_the_numbers_match_the_prompt(self):
        self.states_number(
            "%d minutes" % round(prompts._NEARLY_SPENT_SECONDS / 60),
            "the nearly-spent runtime")
        self.states_number("%d tokens" % prompts._NEARLY_SPENT_TOKENS,
                           "the nearly-spent token figure")


class TestTheReadmeCountsTheDemoSections(unittest.TestCase):
    """The README advertised "22 sections" while the tour had 23.

    A number written once and never derived goes stale on the next
    addition, and this one is the first thing an evaluator reads.
    """

    def test_the_count_matches_the_tour(self):
        root = Path(__file__).resolve().parents[2]
        demo = (root / "docs" / "C2_DEMO.md").read_text()
        readme = (root / "README.md").read_text()
        sections = len(re.findall(r"^## \d+\. ", demo, re.M))
        found = re.search(r"\u2014 (\d+) sections covering", readme)
        self.assertIsNotNone(found, "the README no longer states a count")
        self.assertEqual(int(found.group(1)), sections)

    def test_the_badge_counts_the_figures(self):
        # Three numbers in the README now derive from the repository:
        # the section count, and the stills and GIFs in the badge. Each
        # one written by hand is one that goes stale on the next addition.
        root = Path(__file__).resolve().parents[2]
        shots = root / "docs" / "screenshots"
        readme = (root / "README.md").read_text()
        found = re.search(r"C2%20Demo-(\d+)%20stills%20%2B%20(\d+)%20GIFs",
                          readme)
        self.assertIsNotNone(found, "the README no longer counts the figures")
        self.assertEqual(int(found.group(1)),
                         len(list(shots.glob("*.png"))), "stills")
        self.assertEqual(int(found.group(2)),
                         len(list(shots.glob("*.gif"))), "GIFs")

    def test_the_tour_numbers_its_sections_consecutively(self):
        # A gap or a repeat means the table of contents and the headings
        # have drifted apart.
        root = Path(__file__).resolve().parents[2]
        demo = (root / "docs" / "C2_DEMO.md").read_text()
        numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", demo, re.M)]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))


class TestTheDocsSayHowToSignIn(unittest.TestCase):
    """The page no longer carries the operator token; it asks for it.

    A reader who opens the GUI meets a prompt, so the two pages that tell
    them how to open it say what to enter and where it is kept -- and
    neither may suggest the rejected alternative, a token in the URL.
    """

    def test_both_pages_say_where_the_token_is_kept(self):
        for doc in (README, DEMO_DOC):
            text = doc.read_text()
            self.assertIn("sessionStorage", text, doc.name)
            self.assertIn("`Token:`", text, doc.name)

    def test_no_page_puts_the_token_in_a_url(self):
        for doc in (README, DEMO_DOC, AGENT_DOC):
            text = doc.read_text()
            for needle in ("?t=", "&t=", "token="):
                self.assertNotIn(needle, text, "%s in %s" % (needle, doc.name))


# ── Known limits: the findings the hardening pass left open ──
#
# Each entry is a phrase the section must carry, in the group it belongs to,
# and -- where the code can say -- a function that is True for as long as the
# finding is still open. When someone fixes one, its predicate turns False and
# the test fails until the entry is deleted from the section and from here: the
# section cannot go on calling a fixed thing open. When someone deletes an
# entry from the section, the phrase goes missing. When someone adds a bullet
# without adding it here, the count is off.
#
# The predicates are deliberately narrow. The first draft of the rate-limiting
# one matched "X-RateLimit" header values in a C2 profile example and reported
# a limiter that does not exist, so the ones that can be behavioural are:
# they send the request and look at what comes back.

_C2 = REPO / "software" / "c2"
_BEACON_KEY = bytes(range(32))
_BEACON_TOKEN = "known-limits-probe-token"


def _read(*parts):
    return REPO.joinpath(*parts).read_text()


def _config():
    return yaml.safe_load(_read("configs", "raccoon.yaml"))


class _ProbeServer:
    """A throwaway C2 on the Flask test client, with the globals put back."""

    def __enter__(self):
        self.data_dir = Path(tempfile.mkdtemp())
        self.crypto = c2_server.ServerCrypto(_BEACON_KEY)
        self.app = c2_server.create_app(self.crypto, _BEACON_TOKEN,
                                        self.data_dir)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.auth = {"Authorization": "Bearer " + _BEACON_TOKEN}
        self._clear()
        return self

    def __exit__(self, *exc):
        self._clear()

    def _clear(self):
        for store in (c2_server.agents, c2_server.task_queues,
                      c2_server.history, c2_server.results):
            store.clear()
        c2_server._name_counter = 0

    def post(self, payload):
        reply = self.client.post("/b", data=json.dumps(
            self.crypto.wrap(payload)), content_type="application/json")
        return self.crypto.unwrap(reply.get_json())


def _beacon_cannot_verify_tls():
    text = _read("software", "c2", "beacon.py")
    mentions = re.findall(r"^.*\bverify_ssl\b.*$", text, re.M)
    return (len(mentions) == 1 and "self.verify_ssl = " in mentions[0]
            and "ssl_ctx.verify_mode = ssl.CERT_NONE" in text)


def _a_replayed_result_is_applied_again():
    with _ProbeServer() as srv:
        registered = srv.post({"action": "register", "id": "probe",
                               "hostname": "h", "os": "L", "arch": "x",
                               "user": "u", "pid": 1, "interval": 5})
        captured = {"action": "result", "agent_id": registered["agent_id"],
                    "task_id": "t1", "status": "ok", "output": "first"}
        srv.post(captured)
        c2_server.results["t1"]["output"] = "tampered"
        srv.post(captured)
        return c2_server.results["t1"]["output"] == "first"


def _the_staged_download_is_unchecked():
    sliver = _config()["c2"]["sliver"]
    source = inspect.getsource(SliverManager._stage_implant)
    return (sliver["staging_url"] == "" and sliver["sha256"] == ""
            and "verify=False" in source and "if self.expected_hash:" in source)


def _rdp_hands_request_text_to_a_shell():
    text = _read("software", "c2", "server.py")
    return ("cmd_str, shell=True" in text
            and "echo '{password}' | vncpasswd -f" in text)


def _the_loot_download_reaches_the_data_directory():
    with _ProbeServer() as srv:
        (srv.data_dir / "loot").mkdir()
        (srv.data_dir / "key.pem").write_text("outside-loot")
        reply = srv.client.get("/api/loot/%2e%2e/key.pem", headers=srv.auth)
        return reply.status_code == 200 and reply.data == b"outside-loot"


def _the_server_image_is_root_with_net_admin():
    image = _read("software", "c2", "Dockerfile")
    compose = _read("software", "c2", "docker-compose.yml")
    return (not re.search(r"^\s*USER\s", image, re.M)
            and "NET_ADMIN" in compose and "/tmp/.X11-unix" in compose)


def _file_browser_names_reach_onclick_strings():
    text = _read("software", "c2", "server.py")
    return bool(re.search(
        r"""onclick="[^"\n]*\\'\s*'\s*\+\s*esc\(full""", text))


def _nothing_is_pinned():
    reqs = [_read("software", "requirements.txt"),
            _read("software", "agent", "requirements.txt")]
    image = _read("software", "c2", "Dockerfile")
    pip_block = image.split("RUN pip install", 1)[1].split("\n\n", 1)[0]
    return (not any("==" in line for text in reqs
                    for line in text.splitlines()
                    if not line.lstrip().startswith("#"))
            and not re.search(r"[<>=]", pip_block)
            and re.search(r"NetExec\s*$", image, re.M) is not None)


def _the_old_dependencies_are_still_declared():
    return ("netifaces" in _read("software", "requirements.txt")
            and "ldap3" in _read("software", "c2", "Dockerfile"))


def _there_is_no_size_cap_and_no_rate_limit():
    with _ProbeServer() as srv:
        wrong = {"Authorization": "Bearer not-the-token"}
        codes = {srv.client.get("/api/loot", headers=wrong).status_code
                 for _ in range(60)}
        right = srv.client.get("/api/loot", headers=srv.auth).status_code
        return (srv.app.config.get("MAX_CONTENT_LENGTH") is None
                and codes == {401} and right == 200)


def _the_shipped_config_carries_a_vnc_password():
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "vnc_password":
                    yield value
                yield from walk(value)
    return "raccoon" in list(walk(_config()))


def _the_token_is_compared_with_plain_equality():
    text = _read("software", "c2", "server.py")
    # Only the operator token's own comparison counts. This used to also
    # require that `compare_digest` appeared nowhere in the file, which
    # read as a shortcut for "nothing here compares tokens properly yet".
    # The listener tasking route then added a second, correct comparison,
    # and the shortcut made this probe report the finding fixed while
    # line 350 still held an `==`. A probe that names one comparison has
    # to look at that comparison.
    return "return auth[7:] == operator_token" in text


def _project_files_are_world_readable():
    sources = [REPO / "software" / "main.py", REPO / "software" / "watchdog.py"]
    for sub in ("c2", "agent"):
        # A virtualenv inside the tree is not the project's code, and pip's
        # own os.umask call in one once made this report the file modes fixed.
        sources.extend(p for p in (REPO / "software" / sub).rglob("*.py")
                       if not {".venv", "site-packages"} & set(p.parts))
    no_umask = not any("os.umask" in p.read_text() for p in sources)
    before = os.umask(0o022)
    try:
        with _ProbeServer() as srv:
            c2_server._save_state(srv.data_dir)
            mode = (srv.data_dir / "state.json").stat().st_mode & 0o777
    finally:
        os.umask(before)
    return no_umask and mode == 0o644


def _there_is_no_licence_file():
    return not any(p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING"))
                   for p in REPO.iterdir() if p.is_file())


# group -> [(phrase the entry must contain, True-while-open or None)].
# None means nothing in the working tree can show it: the six commits are on
# a GitHub reference, and the deferred minors are properties of tests, of
# prose and of a GUI that this file cannot run. Those are checked for being
# present, in the right group and counted, and no more than that.
def _the_sleep_floor_overrides_a_short_interval():
    # Two halves, and the second is what makes it a defect rather than a
    # policy: the beacon floors its sleep at 10 s, and still reports the
    # configured interval to the server, which sizes its freshness windows
    # from that number.
    text = _read("software", "c2", "beacon.py")
    floored = "time.sleep(max(10, delay))" in text
    reports_configured = re.search(r'"interval":\s*self\.interval', text)
    return floored and bool(reports_configured)


_OPEN_FINDINGS = {
    "Would stop a deployment": [
        ("cannot verify TLS at all", _beacon_cannot_verify_tls),
        ("No replay protection", _a_replayed_result_is_applied_again),
        ("staged-implant download", _the_staged_download_is_unchecked),
        ("`shell=True`", _rdp_hands_request_text_to_a_shell),
        ("loot download escapes its directory",
         _the_loot_download_reaches_the_data_directory),
        ("server image runs as root", _the_server_image_is_root_with_net_admin),
    ],
    "Would stop a release": [
        ("handler-body injections", _file_browser_names_reach_onclick_strings),
        ("Nothing is pinned", _nothing_is_pinned),
        ("Two dependencies", _the_old_dependencies_are_still_declared),
        ("No request-size cap and no rate limiting",
         _there_is_no_size_cap_and_no_rate_limit),
        ("`vnc_password`", _the_shipped_config_carries_a_vnc_password),
    ],
    "Housekeeping, but visible": [
        ("compared with `==`", _the_token_is_compared_with_plain_equality),
        ("land at `0644`", _project_files_are_world_readable),
        ("sleep floor of 10 s", _the_sleep_floor_overrides_a_short_interval),
        ("no `LICENSE` file", _there_is_no_licence_file),
        ("Six commits", None),
    ],
    "Found while hardening, not by the audit": [
        ("A correction to the audit's severity", None),
    ],
    "Minor, deferred": [
        ("`_handle_result` still does bookkeeping", None),
        ("unit-file test", None),
        ("operator listener runs unsupervised", None),
        ("PowerShell launchers are unverified", None),
        ("no-echo test helper", None),
        ("unhashable `agent_id`", None),
        ("`OSError`", None),
        ("do not normalise `..`", None),
        ("line continuation", None),
        ("`beacon.decode_key`'s docstring", None),
        ("`except ImportError`", None),
        ("loopback-equivalent", None),
        ("Settings panel", None),
        ("`aiCall()`", None),
        ("`tokenRejected`", None),
        ("route-walk test", None),
        ("scanner flags an `echo`", None),
        ("single-dash", None),
    ],
}

# Nineteen findings were deferred; two say nearly the same thing and are one
# entry, so eighteen entries stand for nineteen. The section says both.
_DEFERRED_FINDINGS = 19
_DEFERRED_MERGED = 1


class TestTheKnownLimitsRecordTheOpenFindings(_DocCase):
    def _groups(self):
        body = self.doc.split("\n## Known limits\n", 1)[1].split("\n## ", 1)[0]
        parts = re.split(r"^#### (.+)$", body, flags=re.M)
        return {parts[i].strip(): parts[i + 1] for i in range(1, len(parts), 2)}

    def test_the_section_holds_exactly_the_findings_that_are_still_open(self):
        groups = self._groups()
        self.assertEqual(sorted(groups), sorted(_OPEN_FINDINGS),
                         "the severity groups in Known limits changed")
        for group, entries in _OPEN_FINDINGS.items():
            flat = " ".join(groups[group].split()).lower()
            bullets = re.findall(r"^- \*\*", groups[group], re.M)
            self.assertEqual(len(bullets), len(entries),
                             "%s: the section has %d entries, the record %d"
                             % (group, len(bullets), len(entries)))
            for phrase, still_open in entries:
                with self.subTest(group=group, entry=phrase):
                    self.assertIn(" ".join(phrase.split()).lower(), flat,
                                  "%r is not under %r" % (phrase, group))
                    if still_open is not None:
                        self.assertTrue(
                            still_open(),
                            "%r is no longer true of the code: it has been "
                            "fixed. Delete it from Known limits and from "
                            "_OPEN_FINDINGS." % phrase)
        deferred = " ".join(groups["Minor, deferred"].split()).lower()
        self.assertIn("nineteen", deferred)
        self.assertEqual(
            len(_OPEN_FINDINGS["Minor, deferred"]) + _DEFERRED_MERGED,
            _DEFERRED_FINDINGS, "the merge count and the entry count differ")


class _ParserReached(Exception):
    def __init__(self, parser):
        Exception.__init__(self)
        self.parser = parser


# Why this calls main() at all, and why the create_app patch must stay:
# main() builds its parser inline, and extracting a _build_parser() would be a
# production change. So the test runs main() and stops it at parse_args, which
# is the first thing it does. That is only safe while it stays the first
# thing. create_app is patched to raise so that if someone puts work ahead of
# the parse -- reads a key, binds a socket -- this fails loudly instead of
# starting a server from inside the test suite. Do not "simplify" the patch
# away: it is the guard that makes calling main() acceptable.
def _server_parser():
    """The argument parser main() builds, without main() going any further.

    main() builds its parser and parses in one function, and it is the first
    thing the function does. Stopping at parse_args hands back the real
    parser -- every option and default exactly as the server would see them --
    before a key is read, a directory made or a socket opened. create_app is
    patched to fail as well, so that if main() is ever reordered to do
    something before it parses, the test fails instead of serving.
    """
    def stop(self, *args, **kwargs):
        raise _ParserReached(self)

    went_on = AssertionError("main() went past its argument parser")
    with patch.object(argparse.ArgumentParser, "parse_args", stop), \
            patch.object(c2_server, "create_app", side_effect=went_on):
        try:
            c2_server.main()
        except _ParserReached as reached:
            return reached.parser
    raise AssertionError("main() returned without parsing its arguments")


def _fenced(text, *languages):
    """The bodies of the fenced code blocks tagged with one of `languages`."""
    return [body for lang, body in re.findall(r"^```(\w*)\n(.*?)^```", text,
                                              re.M | re.S)
            if lang in languages]


class TestTheRedirectorPageMatchesTheServer(unittest.TestCase):
    """docs/REDIRECTOR.md hands a reader configuration to paste. Its flags and
    ports were once read off the parser by hand; these read them again."""

    @classmethod
    def setUpClass(cls):
        cls.text = REDIRECTOR_DOC.read_text()
        cls.options = _server_parser()._option_string_actions

    def default(self, flag):
        if flag not in self.options:
            self.fail("the server's parser has no %s, which the page's "
                      "proxy targets are checked against" % flag)
        return self.options[flag].default

    def test_the_page_exists_and_the_readme_links_it(self):
        self.assertTrue(REDIRECTOR_DOC.is_file(), "docs/REDIRECTOR.md is gone")
        # A markdown link, not the bare path: the path also appears in prose.
        self.assertTrue(
            re.search(r"\]\((?:\./)?docs/REDIRECTOR\.md(?:#[^)]*)?\)",
                      README.read_text()),
            "README.md does not link docs/REDIRECTOR.md")

    def _proxy_targets(self):
        """(directive, target) for each proxy_pass in an nginx block and each
        reverse_proxy in a Caddy block. Anchored to the start of a line, so
        prose that mentions `proxy_pass` is not a target."""
        found = []
        for body in _fenced(self.text, "nginx"):
            found += [("proxy_pass", t) for t in re.findall(
                r"^\s*proxy_pass\s+(\S+?);?\s*$", body, re.M)]
        for body in _fenced(self.text, "caddyfile", "caddy"):
            found += [("reverse_proxy", t) for t in re.findall(
                r"^\s*reverse_proxy\s+(\S+)", body, re.M)]
        return found

    def test_every_proxy_target_is_the_agent_port_and_none_is_the_operators(self):
        agent = self.default("--port")
        operator = self.default("--operator-port")
        self.assertNotEqual(agent, operator,
                            "the two sockets share a default port, so the "
                            "page cannot tell a proxy target from the GUI")
        targets = self._proxy_targets()
        for directive in ("proxy_pass", "reverse_proxy"):
            self.assertTrue(any(d == directive for d, _ in targets),
                            "no %s target found in the page" % directive)
        for directive, target in targets:
            port = re.search(r":(\d+)$", target)
            self.assertIsNotNone(port, "%s %s names no port" %
                                 (directive, target))
            self.assertNotEqual(int(port.group(1)), operator,
                                "%s %s points at the operator interface"
                                % (directive, target))
            self.assertEqual(int(port.group(1)), agent,
                             "%s %s is not the agent socket's default port"
                             % (directive, target))

    def _flag_table(self):
        """(flag, default) for each row of the 'two sockets' table."""
        rows = _rows_under(self.text, "## The two sockets")
        found = []
        for row in rows[1:]:
            cells = re.match(r"\|\s*`(--[a-z][a-z0-9-]*)`\s*\|\s*`([^`]*)`\s*\|",
                             row)
            self.assertIsNotNone(cells, "a flag-table row names no flag or "
                                 "no default in backticks: %s" % row)
            found.append((cells.group(1), cells.group(2)))
        return found

    def test_every_default_in_the_flag_table_is_the_parsers(self):
        table = self._flag_table()
        self.assertEqual(
            sorted(flag for flag, _ in table),
            ["--host", "--operator-host", "--operator-port", "--port"],
            "the flag table no longer covers the four socket flags")
        for flag, shown in table:
            self.assertEqual(shown, str(self.default(flag)),
                             "the table gives %s a default of %s; the "
                             "parser's is %s"
                             % (flag, shown, self.default(flag)))

    def test_every_default_the_prose_states_is_the_parsers(self):
        # "`--port`, default `8443`": the sentence form of the same fact.
        flat = re.sub(r"\n\s*>?\s*", " ", self.text)
        stated = re.findall(r"`(--[a-z][a-z0-9-]*)`, default `([^`]+)`", flat)
        self.assertTrue(stated, "the page no longer states a default in prose")
        for flag, shown in stated:
            self.assertEqual(shown, str(self.default(flag)),
                             "the prose gives %s a default of %s; the "
                             "parser's is %s"
                             % (flag, shown, self.default(flag)))

    def test_the_ssh_forward_names_the_operator_interface(self):
        # The startup banner builds this line from the operator port and host
        # (server.py: "ssh -L {operator_port}:{operator_host}:{operator_port}
        # <user>@<this-host>"). The banner is printed deep inside main(),
        # past the point this file stops it, so the line is rebuilt here from
        # the parser's defaults rather than read from the banner.
        port = self.default("--operator-port")
        host = self.default("--operator-host")
        # Any other option on the command (ssh -N -L ...) is the page's own
        # business; the forward's three fields are the claim.
        forwards = re.findall(r"^ssh\b[^\n]*?-L (\S+) <user>@<this-host>",
                              self.text, re.M)
        self.assertTrue(forwards, "the page no longer shows an ssh forward")
        for forward in forwards:
            self.assertEqual(forward, "%s:%s:%s" % (port, host, port),
                             "the ssh forward is not the banner's form for "
                             "the operator interface's defaults")
        opened = re.findall(r"://localhost:(\d+)", self.text)
        self.assertTrue(opened, "the page no longer says where to open the GUI")
        for shown in opened:
            self.assertEqual(shown, str(port), "the page opens localhost:%s; "
                             "the operator interface is on %s" % (shown, port))

    def _server_flags(self):
        """The flags the page applies to this server, and nothing else.

        Three places, each one where the subject is unambiguously the server:

        - the flag table's first column;
        - a command line that runs the server (it names software/c2/server.py
          or software.c2.server), with its backslash continuations, up to a
          pipe, `;`, `&&` or comment. Another program's command is not one,
          even in the same code block;
        - an inline code span in prose that is bare flags -- it starts with
          `--` -- or that runs the server. A span led by another command
          (`curl --insecure`, `ssh -L ...`) belongs to that command.

        Everything else is left alone: other programs' flags, the nginx and
        Caddy blocks, a "--" in a sentence.
        """
        flag = r"(?<![^\s])(--[a-z][a-z0-9-]*)"
        runs_server = re.compile(r"software[/.]c2[/.]server")
        flags = {f for f, _ in self._flag_table()}

        fenced = [b for _, b in re.findall(r"^```(\w*)\n(.*?)^```", self.text,
                                           re.M | re.S)]
        for body in fenced:
            for command in re.sub(r"\\\n", " ", body).splitlines():
                ran = runs_server.search(command)
                if ran:
                    rest = re.split(r"[|;]|&&|\s#", command[ran.end():])[0]
                    flags.update(re.findall(flag, rest))

        prose = re.sub(r"^```\w*\n.*?^```", "", self.text, flags=re.M | re.S)
        for span in re.findall(r"`([^`]+)`", prose):
            if span.lstrip().startswith("--") or runs_server.search(span):
                flags.update(re.findall(r"(?<![^\s])(--[a-z][a-z0-9-]*)", span))
        return flags

    def test_every_flag_the_page_applies_to_the_server_is_an_option_of_it(self):
        flags = self._server_flags()
        self.assertTrue(flags, "no server flag found in the page")
        for flag in sorted(flags):
            self.assertTrue(flag in self.options,
                            "the page names %s for the server; the server's "
                            "parser has no such option" % flag)


if __name__ == "__main__":
    unittest.main()

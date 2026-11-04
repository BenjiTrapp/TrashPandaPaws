#!/usr/bin/env python3
"""
Tests for the fail-closed scope check: target extraction from arbitrary
command lines, containment against the allowlist, denylist precedence, and
refusal of every argument whose real target cannot be determined.
"""

import shlex
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import scope

ALLOW = ["10.0.1.0/24", "10.0.2.0/24"]
DENY = ["10.0.9.0/24"]


def _scope():
    return scope.Scope(allow=ALLOW, deny=DENY)


def _none(host):
    return None


class TestExtraction(unittest.TestCase):
    def test_extracts_plain_ipv4(self):
        found, unknown = scope.extract_targets("nmap -sV 10.0.1.5")
        self.assertEqual(found, ["10.0.1.5"])
        self.assertEqual(unknown, [])

    def test_extracts_cidr(self):
        found, _ = scope.extract_targets("netscan 10.0.1.0/24")
        self.assertEqual(found, ["10.0.1.0/24"])

    def test_extracts_both_range_forms(self):
        self.assertEqual(scope.extract_targets("nmap 10.0.1.1-254")[0], ["10.0.1.1-254"])
        self.assertEqual(
            scope.extract_targets("nmap 10.0.1.1-10.0.1.254")[0], ["10.0.1.1-10.0.1.254"])

    def test_comma_separated_targets_are_split(self):
        """Review Focus 1: unerwartetes Format, nicht böswilliges Ziel."""
        found, unknown = scope.extract_targets("nmap 10.0.1.5,10.0.2.7")
        self.assertEqual(found, ["10.0.1.5", "10.0.2.7"])
        self.assertEqual(unknown, [])

    def test_bracketed_ipv6_literal_is_recognised(self):
        found, unknown = scope.extract_targets("nmap -6 [fd00::1]")
        self.assertEqual(found, ["fd00::1"])
        self.assertEqual(unknown, [])

    def test_bare_ipv6_literal_is_recognised(self):
        self.assertEqual(scope.extract_targets("nmap -6 fd00::1")[0], ["fd00::1"])

    def test_dotted_hostname_is_a_target(self):
        found, unknown = scope.extract_targets("nmap dc01.corp.local")
        self.assertEqual((found, unknown), (["dc01.corp.local"], []))

    def test_ports_and_flag_values_are_not_targets(self):
        found, unknown = scope.extract_targets("nmap -p 22,80,8080 -T4 10.0.1.5")
        self.assertEqual((found, unknown), (["10.0.1.5"], []))
        found, unknown = scope.extract_targets("nmap -p 1-1000 --max-retries 2 10.0.1.5")
        self.assertEqual((found, unknown), (["10.0.1.5"], []))

    def test_program_name_is_not_a_hostname(self):
        found, unknown = scope.extract_targets("secretsdump.py -h")
        self.assertEqual((found, unknown), ([], []))

    def test_program_name_after_separator_is_not_a_hostname(self):
        found, unknown = scope.extract_targets("nmap 10.0.1.5 && secretsdump.py 10.0.1.6")
        self.assertEqual((found, unknown), (["10.0.1.5", "10.0.1.6"], []))

    def test_quoted_target_is_unquoted(self):
        self.assertEqual(scope.extract_targets("nmap '10.0.9.5'")[0], ["10.0.9.5"])
        self.assertEqual(
            scope.extract_targets('nmap "10.0.1.5 10.0.9.5"')[0], ["10.0.1.5", "10.0.9.5"])

    def test_user_at_host_and_url_forms_yield_the_host(self):
        for cmd, want in (
            ("ssh root@10.0.9.5", "10.0.9.5"),
            ("secretsdump.py corp/admin:pw@10.0.9.5", "10.0.9.5"),
            ("curl http://10.0.9.5/admin", "10.0.9.5"),
            ("curl https://10.0.9.5:8443/x", "10.0.9.5"),
            ("curl http://[fd00::1]:80/", "fd00::1"),
            ("curl http://user:pw@dc01.corp.local/", "dc01.corp.local"),
        ):
            self.assertEqual(scope.extract_targets(cmd)[0], [want], cmd)

    def test_targets_inside_a_quoted_command_string_are_found(self):
        found, unknown = scope.extract_targets("sh -c 'nmap 10.0.1.5; nmap 10.0.9.5'")
        self.assertEqual((found, unknown), (["10.0.1.5", "10.0.9.5"], []))

    def test_userinfo_cannot_disguise_the_real_host(self):
        self.assertEqual(
            scope.extract_targets("curl http://10.0.1.5@10.0.9.5/")[0], ["10.0.9.5"])

    def test_flag_with_equals_value_is_scanned(self):
        self.assertEqual(scope.extract_targets("tool --rhosts=10.0.9.5")[0], ["10.0.9.5"])

    def test_target_inside_url_is_not_mistaken_for_a_file(self):
        found, unknown = scope.extract_targets("curl http://10.0.1.5/robots.txt")
        self.assertEqual((found, unknown), (["10.0.1.5"], []))

    def test_never_raises_on_hostile_input(self):
        for cmd in ("", " ", "'", "nmap 'unterminated", "\x00", "nmap \udcff", "a" * 10000,
                    None, 5, b"nmap 10.0.1.5", "nmap http://[::1", "nmap 10.0.1.1-"):
            found, unknown = scope.extract_targets(cmd)
            self.assertIsInstance(found, list)
            self.assertIsInstance(unknown, list)
            result = _scope().check(cmd, _none)
            self.assertIsInstance(result, (str, type(None)))
            if unknown:
                self.assertIsInstance(result, str)


class TestUnresolvable(unittest.TestCase):
    """Every shape whose real target cannot be read off the command line."""

    def _unknown(self, cmd):
        return scope.extract_targets(cmd)[1]

    def test_target_file_flags_are_unresolvable(self):
        for cmd in ("nmap -iL ziele.txt", "nmap -iLziele", "nmap --target-file /tmp/t",
                    "nmap --target-file=/tmp/t", "nmap --targets x", "nmap -iR 100",
                    "nmap -iL -", "nmap 10.0.1.5 -"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_a_suffixed_filename_without_a_flag_needs_require_target(self):
        # "targets.txt" and "cat notes.txt" are the same shape; only the
        # classification of the command tells them apart.
        for cmd in ("nxc smb targets.txt", "nxc smb t.lst", "nxc smb T.LIST"):
            self.assertIsNone(_scope().check(cmd, lambda h: None), cmd)
            self.assertIsNotNone(
                _scope().check(cmd, lambda h: None, require_target=True), cmd)

    def test_an_address_in_the_same_word_as_a_file_is_still_checked(self):
        for cmd in ("nmap 10.0.9.5,hosts.txt", "nmap hosts.txt,10.0.9.5"):
            self.assertIsNotNone(_scope().check(cmd, lambda h: None), cmd)

    def test_shell_expansion_is_unresolvable(self):
        for cmd in ("nmap $TARGET", "nmap $(cat /tmp/t)", "nmap `cat /tmp/t`",
                    "nmap 10.0.{1,9}.5", "nmap http://10.0.1.5\\\\@10.0.9.5/",
                    "curl http://%31%30.0.9.5/", "nmap 10.0.1.5 < /tmp/t"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_unbalanced_quotes_are_unresolvable(self):
        self.assertTrue(self._unknown("nmap 'unterminated 10.0.9.5"))

    def test_deeply_nested_quoting_is_unresolvable(self):
        cmd = "nmap 10.0.9.5"
        for _ in range(10):
            cmd = "sh -c " + shlex.quote(cmd)
        self.assertTrue(self._unknown(cmd))

    def test_non_ascii_digits_are_unresolvable(self):
        self.assertTrue(self._unknown("nmap \uff11\uff10.0.9.5"))

    def test_address_shaped_but_unparseable(self):
        for cmd in ("nmap 10.0.1.256", "nmap 10.0.9.5:80", "nmap 10.0.1.1-300",
                    "nmap 10.0.1.250-10.0.1.2", "nmap 10.0.1-3.5", "nmap 10.0.1.1-5.2-9",
                    "nmap [fd00::1]:80", "nmap 1.2.3.4.5", "nmap 10.0.1.0/33",
                    "nmap 10.0.1.5;10.0.9.5x", "nmap dc01.corp.local:445",
                    "curl dc01.corp.local/admin", "curl dc01:8080", "nmap fe80::1%eth0"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_semicolon_glued_targets_are_split_not_missed(self):
        found, unknown = scope.extract_targets("nmap 10.0.1.5;nmap 10.0.9.5")
        self.assertEqual((found, unknown), (["10.0.1.5", "10.0.9.5"], []))

    def test_newline_starts_a_new_command(self):
        found, unknown = scope.extract_targets("nmap 10.0.1.5\nsecretsdump.py 10.0.9.5")
        self.assertEqual((found, unknown), (["10.0.1.5", "10.0.9.5"], []))

    def test_output_redirection_target_is_not_scanned(self):
        found, unknown = scope.extract_targets("nmap 10.0.1.5 > scan.txt 2>&1")
        self.assertEqual((found, unknown), (["10.0.1.5"], []))

    def test_octet_list_cannot_hide_behind_comma_splitting(self):
        for cmd in ("nmap 172,10.0.0.1", "nmap 10.1,9.0.5", "nmap 10.0.1,2.5",
                    "nmap 10.0.1.5,80"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_paths_alone_are_not_refused(self):
        # A path is not a target. Reading files is most of what there is to
        # do on a host, and refusing every path refused all of it.
        for cmd in ("cat /etc/shadow", "ls -la /opt", "cat ./notes.txt",
                    "cat ../notes", "cat ~/.ssh/id_rsa", "cat notes.txt",
                    "grep -i pass /var/log/auth.log", "find / -name id_rsa",
                    "strings /tmp/dump.bin", "nmap -oA /tmp/out 10.0.1.5"):
            self.assertIsNone(_scope().check(cmd, lambda h: None), cmd)

    def test_a_target_file_flag_is_still_unresolvable(self):
        for cmd in ("nmap --target-file /tmp/x", "nmap --includefile=/tmp/x",
                    "masscan -c conf/hosts 10.0.1.0/24"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_an_exclude_file_is_not_a_target_file(self):
        # It can only narrow a scan, never widen it, so its contents cannot
        # put a host outside the scope into the command. Refusing it would
        # cost an unactionable retry.
        for cmd in ("nmap --excludefile /tmp/x 10.0.1.5",
                    "nmap --excludefile=/tmp/x 10.0.1.5"):
            self.assertIsNone(
                _scope().check(cmd, lambda h: None, require_target=True), cmd)

    def test_an_address_beside_a_path_is_still_checked(self):
        self.assertIsNotNone(
            _scope().check("nxc smb 10.0.9.5,/tmp/x", lambda h: None))

    def test_a_targetless_scan_says_so_and_how_to_fix_it(self):
        reason = _scope().check("nxc smb /tmp/hosts", _none, require_target=True)
        self.assertIn("no target", reason)
        self.assertIn("individually", reason)

    def test_paths_that_are_not_arguments_still_pass(self):
        for cmd in ("/usr/bin/nmap 10.0.1.5", "./run.sh 10.0.1.5", "~/bin/scan 10.0.1.5",
                    "nmap 10.0.1.5 > /tmp/out", "nmap 10.0.1.5 2>/tmp/err",
                    "nmap 10.0.1.0/24", "curl http://10.0.1.5/a/b",
                    "curl http://10.0.1.5/robots.txt"):
            self.assertIsNone(_scope().check(cmd, _none), cmd)

    def test_glob_characters_are_unresolvable(self):
        for cmd in ("nmap dc0[1-5].corp.local", "nmap dc*.corp.local",
                    "nmap dc0?.corp.local", "nmap *.corp.local", "nmap 10.0.1.*",
                    "nmap 10.0.1.[5-9]", "nmap dc0[1:5].corp.local",
                    "nmap 10.0.1.5,dc[1].corp.local", "tool --rhosts=dc*.corp.local",
                    "nmap [fd00::g]", "nmap [fd00::1", "nmap fd00::1]",
                    "curl http://dc0[1-5].corp.local/"):
            self.assertTrue(self._unknown(cmd), cmd)

    def test_glob_refusal_names_the_pattern(self):
        self.assertIn("dc0[1-5].corp.local",
                      _scope().check("nmap dc0[1-5].corp.local", _none))

    def test_legitimate_bracket_and_query_uses_still_pass(self):
        s = scope.Scope(allow=ALLOW + ["fd00::/64"], deny=DENY)
        for cmd in ("nmap -6 [fd00::1]", "nmap 10.0.1.5,[fd00::2]", "ssh root@[fd00::1]",
                    "curl http://[fd00::1]:80/", "curl 'http://10.0.1.5/x?a=b*&c[]=1'"):
            self.assertIsNone(s.check(cmd, _none), cmd)

    def test_check_names_the_unresolvable_argument(self):
        reason = _scope().check("nmap -iL ziele.txt 10.0.1.5", _none)
        self.assertIn("-iL", reason)
        self.assertIn("individually", reason)


class TestNumericAddressForms(unittest.TestCase):
    """libc accepts hex, octal, decimal and short forms; the check must see
    the address the tool will actually connect to."""

    def test_alternate_spellings_are_resolved_not_skipped(self):
        s = scope.Scope(allow=["10.0.1.0/24"], deny=[])
        # 10.0.1.5 spelled four ways
        for spelled in ("0x0a000105", "167772421", "012.0.1.5", "10.0.0x1.5", "10.0.261"):
            self.assertIsNone(s.check("nmap " + spelled, _none), spelled)

    def test_alternate_spelling_of_denied_host_is_refused(self):
        for spelled in ("0x0a000905", "167774469", "012.0.9.5", "10.0.9.5"):
            reason = _scope().check("nmap " + spelled, _none)
            self.assertIsNotNone(reason, spelled)
            self.assertIn(spelled, reason)

    def test_zero_is_the_local_host_not_a_port(self):
        self.assertIsNotNone(_scope().check("nmap 0", _none))
        self.assertIsNotNone(_scope().check("nmap 0.0.0.0", _none))

    def test_small_bare_numbers_are_ports_not_hosts(self):
        self.assertIsNone(_scope().check("nmap -p 80 --top-ports 100 10.0.1.5", _none))

    def test_ipv4_mapped_ipv6_is_judged_as_ipv4(self):
        self.assertIsNotNone(_scope().check("nmap -6 ::ffff:10.0.9.5", _none))
        self.assertIsNone(_scope().check("nmap -6 ::ffff:10.0.1.5", _none))


class TestFailClosed(unittest.TestCase):
    def test_target_file_flag_is_rejected_on_its_own(self):
        # A flag that names a file of targets is refused with no help from
        # the caller, because the flag itself says what the file is.
        for cmd in ("nmap -iL ziele.txt 10.0.1.5",
                    "nmap --target-file /tmp/t",
                    "masscan -c /tmp/conf 10.0.1.0/24",
                    "masscan -c/tmp/conf 10.0.1.0/24"):
            self.assertIsNotNone(_scope().check(cmd, lambda h: None), cmd)

    def test_a_positional_target_file_needs_require_target(self):
        # `nxc smb targets.txt` names no checkable target, but the word is
        # just a path — nothing in it says "these are targets". Refusing
        # every path, which this used to do, also refused `cat notes.txt`
        # and `ls /opt`, so the agent could not read a file at all. The
        # router asks for require_target on commands the classifier calls a
        # scan, and that is what catches this.
        cmd = "nxc smb targets.txt -u a -p b"
        self.assertIsNone(_scope().check(cmd, lambda h: None))
        self.assertIsNotNone(
            _scope().check(cmd, lambda h: None, require_target=True))

    def test_hostname_without_finding_is_rejected(self):
        self.assertIsNotNone(_scope().check("nmap -sV dc01.corp.local", lambda h: None))

    def test_hostname_with_in_scope_finding_is_allowed(self):
        self.assertIsNone(
            _scope().check("nmap -sV fs02.corp.local", lambda h: "10.0.1.20"))

    def test_hostname_resolving_outside_scope_is_rejected(self):
        self.assertIsNotNone(
            _scope().check("nmap -sV dc01.corp.local", lambda h: "10.0.9.1"))

    def test_command_without_any_target_is_allowed(self):
        self.assertIsNone(_scope().check("whoami", lambda h: None))

    def test_in_scope_target_is_allowed(self):
        self.assertIsNone(_scope().check("nmap -sV 10.0.1.5", lambda h: None))

    def test_out_of_scope_target_is_rejected(self):
        self.assertIsNotNone(_scope().check("nmap -sV 172.16.0.5", lambda h: None))

    def test_cidr_wider_than_allowlist_is_rejected(self):
        self.assertIsNotNone(_scope().check("netscan 10.0.0.0/8", lambda h: None))

    def test_range_crossing_scope_boundary_is_rejected(self):
        self.assertIsNotNone(
            _scope().check("nmap 10.0.1.250-10.0.9.5", lambda h: None))

    def test_deny_beats_allow(self):
        s = scope.Scope(allow=["10.0.0.0/16"], deny=["10.0.9.0/24"])
        self.assertIsNone(s.check("nmap 10.0.1.5", lambda h: None))
        self.assertIsNotNone(s.check("nmap 10.0.9.5", lambda h: None))

    def test_mixed_targets_reject_if_any_is_out_of_scope(self):
        self.assertIsNotNone(
            _scope().check("nmap 10.0.1.5,172.16.0.5", lambda h: None))

    def test_rejection_reason_names_the_offending_target(self):
        reason = _scope().check("nmap -sV 172.16.0.5", lambda h: None)
        self.assertIn("172.16.0.5", reason)

    def test_in_scope_range_and_cidr_are_allowed(self):
        for cmd in ("nmap 10.0.1.1-254", "nmap 10.0.1.1-10.0.2.254", "nmap 10.0.1.128/25",
                    "nmap 10.0.1.0/24,10.0.2.0/24", "nmap 10.0.1.5/32"):
            self.assertIsNone(_scope().check(cmd, _none), cmd)

    def test_denylist_overlap_refuses_even_a_partly_denied_cidr(self):
        s = scope.Scope(allow=["10.0.0.0/16"], deny=["10.0.9.0/24"])
        reason = s.check("nmap 10.0.8.0/22", _none)
        self.assertIn("10.0.8.0/22", reason)
        self.assertIn("10.0.9.0/24", reason)

    def test_denied_range_inside_allowed_range_is_refused(self):
        s = scope.Scope(allow=["10.0.0.0/16"], deny=["10.0.9.0/24"])
        self.assertIsNotNone(s.check("nmap 10.0.8.250-10.0.9.3", _none))

    def test_empty_allowlist_refuses_every_target(self):
        s = scope.Scope(allow=[], deny=[])
        self.assertIsNotNone(s.check("nmap 10.0.1.5", _none))
        self.assertIsNone(s.check("whoami", _none))

    def test_ipv6_target_against_ipv4_allowlist_is_refused_without_raising(self):
        self.assertIsNotNone(_scope().check("nmap -6 fd00::1", _none))
        self.assertIsNotNone(_scope().check("nmap -6 fd00::/64", _none))

    def test_ipv6_allowlist_and_denylist(self):
        s = scope.Scope(allow=["fd00::/64"], deny=["fd00::9/128"])
        self.assertIsNone(s.check("nmap -6 fd00::1", _none))
        self.assertIsNotNone(s.check("nmap -6 fd00::9", _none))
        self.assertIsNotNone(s.check("nmap 10.0.1.5", _none))

    def test_user_at_host_and_url_forms_are_checked(self):
        self.assertIsNotNone(_scope().check("ssh root@10.0.9.5", _none))
        self.assertIsNotNone(_scope().check("curl http://172.16.0.5/x", _none))
        self.assertIsNone(_scope().check("ssh root@10.0.1.5", _none))

    def test_hostname_reason_names_hostname_and_address(self):
        reason = _scope().check("nmap dc01.corp.local", lambda h: "10.0.9.1")
        self.assertIn("dc01.corp.local", reason)
        self.assertIn("10.0.9.1", reason)

    def test_hostname_without_finding_reason_names_hostname(self):
        self.assertIn("dc01.corp.local", _scope().check("nmap dc01.corp.local", _none))

    def test_resolver_receives_the_hostname(self):
        seen = []
        _scope().check("nmap fs02.corp.local", lambda h: seen.append(h) or "10.0.1.20")
        self.assertEqual(seen, ["fs02.corp.local"])

    def test_resolver_returning_garbage_is_refused(self):
        # ["10.0.1.5"] used to be in this list. It is no longer garbage: a
        # resolver may return several addresses, because any dual-stack name
        # resolves to both an A and an AAAA record. See
        # TestMultiAddressHostnames for the contract that replaced it.
        for bad in ("not-an-ip", "10.0.1.0/24", "", 5, "10.0.1.5 10.0.9.5",
                    [], [5], ["10.0.1.5", "not-an-ip"], [["10.0.1.5"]],
                    {"10.0.1.5": 1}, object()):
            self.assertIsNotNone(
                _scope().check("nmap fs02.corp.local", lambda h, b=bad: b), repr(bad))

    def test_resolver_raising_is_refused_not_propagated(self):
        def boom(host):
            raise RuntimeError("db closed")
        self.assertIsNotNone(_scope().check("nmap fs02.corp.local", boom))

    def test_single_label_name_is_resolved_when_a_finding_exists(self):
        finding = {"dc01": "10.0.9.1", "fs02": "10.0.1.20"}.get
        self.assertIsNotNone(_scope().check("nmap dc01", finding))
        self.assertIsNone(_scope().check("nmap fs02", finding))

    def test_single_label_words_without_finding_do_not_block_ordinary_commands(self):
        self.assertIsNone(
            _scope().check("nxc smb 10.0.1.5 -u admin -p secret --shares", _none))

    def test_localhost_needs_a_finding_like_any_hostname(self):
        self.assertIsNotNone(_scope().check("nmap localhost", _none))

    def test_non_string_command_is_refused(self):
        for cmd in (None, 5, b"nmap 10.0.1.5"):
            self.assertIsNotNone(_scope().check(cmd, _none))


class TestExemptionBoundaries(unittest.TestCase):
    """The glob refusal has two deliberate exemptions: a bracketed IPv6
    literal, and a URL's path and query. An exemption inside a fail-closed
    extractor is where a later change quietly opens a hole, so each edge is
    pinned here in both directions: what must stay refused as unreadable
    ("cannot verify") and what must stay readable."""

    UNREADABLE = "cannot verify"

    def _assert_unreadable(self, cmd):
        reason = _scope().check(cmd, _none)
        self.assertIsNotNone(reason, cmd)
        self.assertTrue(reason.startswith(self.UNREADABLE), (cmd, reason))

    def test_brackets_that_are_not_an_ipv6_literal_are_unreadable(self):
        for cmd in ("nmap [*]", "nmap [1-5]", "nmap []", "nmap [fd00::1",
                    "nmap [[fd00::1]]", "nmap a[fd00::1]", "nmap [fd00::1]x",
                    "nmap [fd00::1]*", "nmap [fd00::1]:*", "nmap [fd00::1],dc*",
                    "nmap [fd00::g]", "nmap [1:5]x", "nmap http://[*]/",
                    "nmap http://[fd00::*]/"):
            self._assert_unreadable(cmd)

    def test_valid_ipv6_literal_is_read_and_judged_by_scope(self):
        wide = scope.Scope(allow=["fd00::/64"], deny=[])
        self.assertIsNone(wide.check("nmap -6 [fd00::1]", _none))
        # Read as an address, so refused for being out of scope, not unreadable.
        for cmd in ("nmap -6 [fd00::1]", "nmap -6 [::]"):
            reason = _scope().check(cmd, _none)
            self.assertIsNotNone(reason, cmd)
            self.assertFalse(reason.startswith(self.UNREADABLE), reason)
            self.assertIn("not entirely inside the authorised ranges", reason)
        self.assertIn("'::'", _scope().check("nmap -6 [::]", _none))
        self.assertEqual(scope.extract_targets("nmap -6 [::]"), (["::"], []))

    def test_glob_in_url_host_userinfo_port_query_or_fragment_is_unreadable(self):
        for cmd in ("curl http://a*@10.0.1.5/", "curl http://10.0.1.5:8*/",
                    "curl http://10.0.1.5?*", "curl http://10.0.1.5#*",
                    "curl x://dc*.corp.local/", "curl http://dc0[1-5].corp.local/",
                    "curl http:///dc*"):
            self._assert_unreadable(cmd)

    def test_glob_in_url_path_or_query_after_the_host_is_still_readable(self):
        for cmd in ("curl http://10.0.1.5/?a=*", "curl http://10.0.1.5/x[1]",
                    "curl http://10.0.1.5/#*", "curl 'http://10.0.1.5/a?b=c&d[]=*'"):
            self.assertIsNone(_scope().check(cmd, _none), cmd)
            self.assertEqual(scope.extract_targets(cmd)[0], ["10.0.1.5"], cmd)

    def test_unquoted_ampersand_ends_the_url_so_the_rest_is_judged_alone(self):
        self._assert_unreadable("curl http://10.0.1.5/a?b=c&d[]=*")

    def test_readable_url_path_does_not_launder_an_out_of_scope_host(self):
        reason = _scope().check("curl http://172.16.0.5/?a=*", _none)
        self.assertIn("172.16.0.5", reason)
        self.assertFalse(reason.startswith(self.UNREADABLE), reason)


class TestCleanupRefusals(unittest.TestCase):
    """Refusals added when the scan was tightened: each pins one behaviour."""

    def _refused(self, cmd):
        reason = _scope().check(cmd, _none)
        self.assertIsNotNone(reason, cmd)
        return reason

    def test_trailing_at_sign_is_refused_and_named(self):
        self.assertIn("10.0.9.5@", self._refused("nmap 10.0.9.5@"))

    def test_bare_number_as_a_target_is_an_address_not_a_port(self):
        for cmd in ("nmap 22", "nmap 65535"):
            self.assertEqual(scope.extract_targets(cmd)[1], [cmd.split()[1]], cmd)
            self.assertIn("'%s'" % cmd.split()[1], self._refused(cmd))

    def test_bare_number_after_a_flag_is_a_value(self):
        for cmd in ("nmap -p 22 10.0.1.5", "nmap --max-rate 50 10.0.1.5"):
            self.assertIsNone(_scope().check(cmd, _none), cmd)

    def test_file_descriptor_glued_to_a_redirect_is_not_a_target(self):
        for cmd in ("nmap 10.0.1.5 2>/tmp/err", "nmap 10.0.1.5 2>&1",
                    "nmap 10.0.1.5 1>/tmp/out"):
            self.assertIsNone(_scope().check(cmd, _none), cmd)

    def test_bare_number_before_a_spaced_redirect_is_still_refused(self):
        # With a space the shell passes 22 to nmap as an address.
        for cmd in ("nmap 10.0.1.5 22 > /tmp/out", "nmap 10.0.1.5 2 >/tmp/out",
                    "nmap 10.0.1.5 22>/tmp/out", "nmap 10.0.1.5 2>/tmp/err 22"):
            self.assertIn("cannot verify", self._refused(cmd), cmd)

    def test_catch_all_refusal_names_the_command(self):
        def boom(host):
            raise RuntimeError("resolver down")
        reason = _scope().check("nmap dc01.corp", boom)
        self.assertIn("RuntimeError", reason)
        self.assertIn("nmap dc01.corp", reason)

    def test_catch_all_refusal_clips_a_long_command(self):
        def boom(host):
            raise RuntimeError("resolver down")
        reason = _scope().check("nmap dc01 " + "x" * 5000, boom)
        self.assertIn("scope check failed", reason)
        self.assertLess(len(reason), 300)

    def test_zone_id_is_never_trimmed_to_a_bare_address(self):
        with self.assertRaises(ValueError):
            scope._parse_networks("fe80::1%eth0")
        self.assertIn("fe80::1%eth0", self._refused("nmap fe80::1%eth0"))

    def test_long_unresolvable_argument_is_clipped_in_the_reason(self):
        arg = "10.0.9.5:" + "9" * 5000
        reason = self._refused("nmap " + arg)
        self.assertIn(arg[:40], reason)
        self.assertNotIn(arg, reason)
        self.assertLess(len(reason), 400)


class TestFlagArity(unittest.TestCase):
    """A bare number is a port or count only after a flag that takes one."""

    def _passes(self, cmds):
        for cmd in cmds:
            self.assertIsNone(_scope().check(cmd, _none), cmd)

    def _refused(self, cmds):
        for cmd in cmds:
            reason = _scope().check(cmd, _none)
            self.assertIsNotNone(reason, cmd)
            self.assertIn("cannot verify", reason, cmd)

    def test_number_after_a_boolean_flag_is_a_target(self):
        self._refused(("nmap -sV 22", "nmap -Pn 22", "nmap -v 80", "nmap -sS 5",
                       "nmap --open 22", "nmap -n 22"))

    def test_number_after_a_numeric_flag_is_a_value(self):
        self._passes(("nmap -p 22 10.0.1.5", "nmap --top-ports 100 10.0.1.5",
                      "nmap -T 4 10.0.1.5", "nmap --host-timeout 30 10.0.1.5",
                      "nmap --ttl 64 10.0.1.5", "nmap --open=22 10.0.1.5"))

    def test_double_dash_ends_option_parsing(self):
        self._refused(("nmap 10.0.1.5 -- 22", "nmap -- -p 22",
                       "nmap 10.0.1.5 -p 22 -- 80"))
        self._passes(("nmap 10.0.1.5 -- 10.0.1.6",))

    def test_number_exemption_is_per_command_not_sticky(self):
        # -p is numeric only as its own flag; the 22 here follows -sV.
        self._refused(("nmap -p 80 -sV 22",))

    def test_the_number_wrappers_take_their_first_argument(self):
        self._passes(("timeout 60 nmap 10.0.1.5", "timeout -s TERM 60 nmap 10.0.1.5",
                      "timeout -k 5 60 nmap 10.0.1.5", "/usr/bin/timeout 60 nmap 10.0.1.5",
                      "sleep 5; nmap 10.0.1.5", "sleep 1.5 && nmap 10.0.1.5",
                      "nmap 10.0.1.5 && sleep 2", "nmap 10.0.1.5 | head 5",
                      "nmap 10.0.1.5 | head -n 5", "nmap 10.0.1.5 | tail -n 20",
                      "nice -n 10 nmap 10.0.1.5"))

    def test_the_wrapper_exemption_does_not_reach_the_wrapped_command(self):
        self._refused(("timeout 60 nmap 22", "timeout 60 nmap -n 22",
                       "nice -n 10 nmap -n 22", "sleep 5 && nmap 22",
                       "sleep 5 nmap 22", "nmap 10.0.1.5 | head 5 22"))

    def test_a_wrapper_name_elsewhere_exempts_nothing(self):
        # Only the program at the start of a command takes the exemption.
        self._refused(("nmap sleep 5", "nmap 10.0.1.5 > out head 22",
                       "nmap 10.0.1.5 head 5"))

    def test_known_over_refusals(self):
        # Fail-closed costs, pinned so a change to them is deliberate. Each
        # reason says to attach the number to its flag; `-c4` then passes.
        self._refused(("hping3 -c 4 10.0.1.5", "xyz --foo 5 10.0.1.5",
                       "nmap -c 4 10.0.1.5", "ssh -o 22 10.0.1.5"))
        self._passes(("hping3 -c4 10.0.1.5", "xyz --foo=5 10.0.1.5"))

    def test_number_hint_tells_the_caller_how_to_comply(self):
        reason = _scope().check("hping3 -c 4 10.0.1.5", _none)
        self.assertIn("attached", reason)
        # The hint is only for numbers; a target-file flag gets the plain one.
        self.assertNotIn(
            "attached", _scope().check("nmap --target-file t", _none))

    def test_flag_arity_is_per_program(self):
        # The same flag is a count for one program and a boolean for another.
        self._passes(("ping -c 4 10.0.1.5", "ping -c 4 -W 2 10.0.1.5",
                      "ping -i 2 -s 56 10.0.1.5", "curl -m 5 http://10.0.1.5",
                      "curl --max-time 5 --retry 3 http://10.0.1.5",
                      "wget -t 3 -T 10 http://10.0.1.5/x", "nc -w 3 10.0.1.5 80",
                      "ncat -i 2 -q 1 10.0.1.5 80", "ssh -p 2222 10.0.1.5",
                      "nc -l -p 4444", "dig +time=5 +tries=2 @10.0.1.5 -x 10.0.1.6"))
        self._refused(("ping 4", "ping -c 4 4", "ping -n 22", "curl 5",
                       "curl -s 5", "wget 3", "ssh 22", "dig 5", "nc 80",
                       "nc -n 22", "nmap -c 4 10.0.1.5", "nmap -w 5 10.0.1.5"))

    def test_host_then_port_programs_take_only_the_second_positional(self):
        self._passes(("nc 10.0.1.5 80", "nc -vz 10.0.1.5 80", "telnet 10.0.1.5 80"))
        self._refused(("nc 80", "telnet 80", "nc 10.0.1.5 22 80",
                       "nc 10.0.1.5 80; nc 22"))

    def test_privilege_and_env_prefixes_do_not_hide_the_program(self):
        self._passes(("sudo timeout 60 nmap 10.0.1.5", "sudo -u alice timeout 60 nmap 10.0.1.5",
                      "doas ping -c 4 10.0.1.5", "doas -u bob ping -c 4 10.0.1.5",
                      "env FOO=1 sleep 5", "FOO=1 sleep 5", "FOO=1 nmap -p 22 10.0.1.5",
                      "sudo ping -c 4 10.0.1.5", "timeout 60 ping -c 4 10.0.1.5",
                      "timeout 60 sleep 5", "watch -n 5 ping -c 4 10.0.1.5",
                      "sudo -n nmap -p 22 10.0.1.5"))

    def test_prefixes_do_not_loosen_the_wrapped_program(self):
        self._refused(("sudo nmap 22", "sudo -u alice nmap -n 22",
                       "doas -u bob nmap -sV 22", "env FOO=1 nmap -Pn 22",
                       "FOO=1 nmap -v 22", "sudo timeout 60 nmap 22",
                       "sudo timeout 60 nmap -n 22", "watch -n 5 nmap 22",
                       "sleep 5 22", "timeout 60 22", "sudo 22"))

    def test_unknown_program_keeps_the_shared_fallback(self):
        # Not in the table: a number is a port only after a shared scanner flag.
        self._passes(("xyz -p 22 10.0.1.5", "xyz --max-rate 50 10.0.1.5"))
        self._refused(("xyz --foo 5 10.0.1.5", "xyz -v 22", "xyz 22"))

    def test_at_sign_with_only_separators_after_it_is_refused(self):
        for cmd in ("nmap 10.0.9.5@,", "nmap 10.0.9.5@,,", "nmap 10.0.9.5@[]"):
            self.assertIn("cannot verify", _scope().check(cmd, _none) or "", cmd)


class TestMultiAddressHostnames(unittest.TestCase):
    """A resolver may return several addresses, and every one must be in scope.

    Refusing a list made hostname targets unusable: any dual-stack name
    resolves to both an A and an AAAA record, so `nmap localhost` and
    `nmap dc01.corp.local` were both refused with "not a single address" even
    when every address was authorised. Accepting a list is not a loosening —
    one address outside still refuses the whole name, because the tool may
    pick that one.
    """

    def test_a_dual_stack_name_inside_the_scope_passes(self):
        sc = scope.Scope(allow=["127.0.0.0/8", "::1/128"], deny=[])
        self.assertIsNone(
            sc.check("nmap localhost", lambda h: ["127.0.0.1", "::1"]))

    def test_a_single_string_still_works(self):
        sc = scope.Scope(allow=["127.0.0.0/8"], deny=[])
        self.assertIsNone(sc.check("nmap localhost", lambda h: "127.0.0.1"))

    def test_a_tuple_works(self):
        sc = scope.Scope(allow=["127.0.0.0/8", "::1/128"], deny=[])
        self.assertIsNone(
            sc.check("nmap localhost", lambda h: ("127.0.0.1", "::1")))

    def test_one_address_outside_refuses_the_whole_name(self):
        reason = _scope().check(
            "nmap dc01.corp.local", lambda h: ["10.0.1.5", "10.9.9.9"])
        self.assertIsNotNone(reason)
        self.assertIn("10.9.9.9", reason)

    def test_one_denied_address_refuses_the_whole_name(self):
        reason = _scope().check(
            "nmap dc01.corp.local", lambda h: ["10.0.1.5", "10.0.9.5"])
        self.assertIsNotNone(reason)
        self.assertIn("denied", reason)

    def test_every_address_inside_passes(self):
        self.assertIsNone(_scope().check(
            "nmap dc01.corp.local", lambda h: ["10.0.1.5", "10.0.2.7"]))

    def test_an_empty_result_is_not_a_pass(self):
        # "I looked and found nothing" is the same position as no finding at
        # all, which must not read as authorisation.
        reason = _scope().check("nmap dc01.corp.local", lambda h: [])
        self.assertIsNotNone(reason)
        self.assertIn("no finding", reason)

    def test_a_mixed_list_with_one_unreadable_entry_is_refused(self):
        reason = _scope().check(
            "nmap dc01.corp.local", lambda h: ["10.0.1.5", "nonsense"])
        self.assertIsNotNone(reason)
        self.assertIn("nonsense", reason)

    def test_the_reason_names_every_address_it_judged(self):
        reason = _scope().check(
            "nmap dc01.corp.local", lambda h: ["10.0.1.5", "172.16.0.1"])
        for addr in ("10.0.1.5", "172.16.0.1"):
            self.assertIn(addr, reason)


class TestReasonsAreBounded(unittest.TestCase):
    """No path echoes attacker-shaped text without a ceiling."""

    LONG = "a" * 5000

    def test_unnamed_hostname_is_clipped(self):
        reason = _scope().check("nmap %s.com" % self.LONG, _none)
        self.assertIn("no finding", reason)
        self.assertLess(len(reason), 400)

    def test_unreadable_resolution_is_clipped(self):
        reason = _scope().check("nmap dc01.corp", lambda host: "10.0.1.5 " * 1000)
        self.assertIn("not an address", reason)
        self.assertLess(len(reason), 400)

    def test_a_long_list_of_real_addresses_is_clipped(self):
        # All inside the scope, so the verdict is a pass; the point is that a
        # resolver returning hundreds of addresses cannot blow up a reason.
        many = ["10.0.9.%d" % i for i in range(1, 200)]   # denied range
        reason = _scope().check("nmap dc01.corp", lambda host: many)
        self.assertIsNotNone(reason)
        self.assertLess(len(reason), 400)

    def test_verdict_label_is_clipped(self):
        host = self.LONG + ".com"
        for addr in ("10.0.9.5", "192.0.2.1"):  # denied, then outside the allowlist
            reason = _scope().check("nmap " + host, lambda h, a=addr: a)
            self.assertIsNotNone(reason, addr)
            self.assertLess(len(reason), 400, addr)


class TestScopeConstruction(unittest.TestCase):
    def test_malformed_allow_entry_raises(self):
        with self.assertRaises(ValueError):
            scope.Scope(allow=["10.0.1.0/24", "ten.zero"], deny=[])

    def test_allow_entry_with_host_bits_set_raises(self):
        with self.assertRaises(ValueError):
            scope.Scope(allow=["10.0.1.5/24"], deny=[])

    def test_malformed_deny_entry_raises(self):
        with self.assertRaises(ValueError):
            scope.Scope(allow=["10.0.1.0/24"], deny=["nonsense"])

    def test_deny_entry_with_host_bits_widens_to_the_network(self):
        s = scope.Scope(allow=["10.0.0.0/16"], deny=["10.0.9.5/24"])
        self.assertIsNotNone(s.check("nmap 10.0.9.200", _none))

    def test_bare_address_is_accepted_as_a_host_entry(self):
        s = scope.Scope(allow=["10.0.1.5"], deny=[])
        self.assertIsNone(s.check("nmap 10.0.1.5", _none))
        self.assertIsNotNone(s.check("nmap 10.0.1.6", _none))




class TestAShareIsAHostFollowedByAPath(unittest.TestCase):
    """`//host/share` names a host; it has no spelling that does not.

    _ADDRESSY matched the `10.0.1` inside `//10.0.1.5/share` before the
    host/path handling got a chance, so every SMB invocation was refused as
    unverifiable -- with advice the model could not follow, because the
    reason says "name each target individually as an IP address" and a
    share has no such form. smbclient and smbloot are both in the shipped
    arsenal. Fail-closed, so not a safety hole, but a capability the agent
    could not reach and a refusal it could not act on.

    The `://` branch already does exactly this for URLs. This is the same
    split for the two share spellings.
    """

    def _why(self, command):
        return _scope().check(command, lambda n: None, require_target=True)

    def test_an_in_scope_share_is_allowed(self):
        for command in ("smbclient //10.0.1.5/share -U a",
                        r"smbclient \\10.0.1.5\share -U a",
                        "smbloot //10.0.1.5/C$ u p ls",
                        "mount -t cifs //10.0.1.5/share /mnt"):
            self.assertIsNone(self._why(command), command)

    def test_an_out_of_scope_share_is_refused_on_its_host(self):
        for command in ("smbclient //10.9.9.9/share -U a",
                        r"smbclient \\10.9.9.9\share"):
            reason = self._why(command)
            self.assertIsNotNone(reason, command)
            self.assertIn("10.9.9.9", reason, command)

    def test_the_share_name_is_not_read_as_a_target(self):
        # `C$` and `ADMIN$` must not become bare hostnames to resolve.
        self.assertIsNone(self._why("smbclient //10.0.1.5/ADMIN$ -U a"))

    def test_a_hostname_share_still_needs_a_finding(self):
        # Same rule as any other name: a host is a target once something
        # ties it to an address in scope.
        reason = self._why("smbclient //fileserver.corp/share")
        self.assertIsNotNone(reason)


class TestAVersionIsNotATarget(unittest.TestCase):
    """`searchsploit dnsmasq 2.90` searches a local database.

    `2.90` and `2.3.4` look addressy enough to be read as targets, so the
    CVE-lookup phase refused its own commands -- observed in a live run,
    where the agent asked for `searchsploit dnsmasq 2.90` and
    `searchsploit vsftpd 2.3.4`. The deferred note called this "number
    arguments are known per program, not per flag"; the per-program table
    exists, and searchsploit was not in it.

    It takes free text, not hosts, so none of its operands are targets.
    """

    def _why(self, command):
        return _scope().check(command, lambda n: None, require_target=False)

    def test_a_version_argument_is_not_a_target(self):
        for command in ("searchsploit dnsmasq 2.90",
                        "searchsploit vsftpd 2.3.4",
                        "searchsploit --json --cve CVE-2011-2523",
                        "searchsploit apache 2.4.49"):
            self.assertIsNone(self._why(command), command)

    def test_a_scanner_still_reads_its_operands_as_targets(self):
        # The exemption is per program, not a general amnesty for numbers.
        self.assertIsNotNone(self._why("nmap 10.9.9.9"))

if __name__ == "__main__":
    unittest.main()

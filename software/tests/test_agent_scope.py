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
            self.assertIsNotNone(_scope().check(cmd, _none) if unknown else "x")


class TestUnresolvable(unittest.TestCase):
    """Every shape whose real target cannot be read off the command line."""

    def _unknown(self, cmd):
        return scope.extract_targets(cmd)[1]

    def test_target_file_arguments(self):
        for cmd in ("nmap -iL ziele.txt", "nmap -iLziele", "nmap --target-file /tmp/t",
                    "nmap --target-file=/tmp/t", "nmap --targets x", "nmap -iR 100",
                    "nxc smb targets.txt", "nxc smb t.lst", "nxc smb T.LIST",
                    "nmap -iL -", "nmap 10.0.1.5 -", "nmap 10.0.1.5,hosts.txt",
                    "nmap hosts.txt,10.0.1.5"):
            self.assertTrue(self._unknown(cmd), cmd)

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
    def test_target_file_argument_is_rejected(self):
        for cmd in ("nmap -iL ziele.txt 10.0.1.5",
                    "nxc smb targets.txt -u a -p b",
                    "nmap --target-file /tmp/t"):
            self.assertIsNotNone(_scope().check(cmd, lambda h: None), cmd)

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
        for bad in ("not-an-ip", "10.0.1.0/24", "", 5, ["10.0.1.5"], "10.0.1.5 10.0.9.5"):
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


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Unit tests for the 802.1X NAC bypass module.

Tests verify the correct sequence and content of system commands
issued during each phase, without requiring root or real interfaces.
All subprocess calls are mocked.
"""

import subprocess
import unittest
from unittest.mock import MagicMock, call, mock_open, patch

from software.nac_bypass import NACBypass, _run, _run_quiet


def _make_config(**overrides):
    cfg = {
        "network": {
            "upstream_iface": "eth0",
            "downstream_iface": "eth1",
            "bridge_name": "br0",
        },
        "nac_bypass": {
            "enabled": True,
            "discovery_timeout": 30,
            "nat_port_range": "61000-62000",
        },
    }
    cfg["nac_bypass"].update(overrides)
    return cfg


def _make_nac(config=None, **overrides):
    nac = NACBypass(config or _make_config(**overrides))
    return nac


def _completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr
    )


class TestInit(unittest.TestCase):
    def test_default_nat_port_range(self):
        cfg = _make_config()
        del cfg["nac_bypass"]["nat_port_range"]
        nac = NACBypass(cfg)
        self.assertEqual(nac.nat_port_range, "61000-62000")

    def test_custom_nat_port_range(self):
        nac = _make_nac(nat_port_range="50000-51000")
        self.assertEqual(nac.nat_port_range, "50000-51000")

    def test_initial_phase(self):
        nac = _make_nac()
        self.assertEqual(nac._phase, "idle")

    def test_interfaces_from_config(self):
        nac = _make_nac()
        self.assertEqual(nac.upstream, "eth0")
        self.assertEqual(nac.downstream, "eth1")
        self.assertEqual(nac.bridge, "br0")


class TestPhase1EapolForwarding(unittest.TestCase):
    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_eapol_writes_group_fwd_mask(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.enable_eapol_forwarding()

        handle = open
        handle.assert_called_once_with(
            "/sys/class/net/br0/bridge/group_fwd_mask", "w"
        )
        handle().write.assert_called_once_with("8")

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_eapol_fallback_to_ip_link(self, mock_open_fn, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.enable_eapol_forwarding()

        mock_rq.assert_any_call("ip link set br0 type bridge group_fwd_mask 8")

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_eapol_ebtables_accept_rule(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.enable_eapol_forwarding()

        mock_rq.assert_any_call(
            "ebtables -t filter -D FORWARD -d 01:80:c2:00:00:03 -j DROP"
        )
        mock_run.assert_any_call(
            "ebtables -t filter -A FORWARD -d 01:80:c2:00:00:03 -j ACCEPT",
            check=False,
        )

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_eapol_sets_phase(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.enable_eapol_forwarding()
        self.assertEqual(nac._phase, "eapol")


class TestPhase2Discovery(unittest.TestCase):
    @patch("software.nac_bypass._run")
    def test_discovery_uses_tcp_syn_filter(self, mock_run):
        mock_run.return_value = _completed(
            stderr="11:22:33:44:55:66 > aa:bb:cc:dd:ee:ff, IPv4"
        )
        nac = _make_nac()
        nac.implant_mac = "aa:bb:cc:dd:ee:ff"
        nac._discover_downstream_mac()

        cmd = mock_run.call_args[0][0]
        self.assertIn("tcp[13] & 2 != 0", cmd)

    @patch("software.nac_bypass._run")
    def test_discovery_skips_broadcast_mac(self, mock_run):
        mock_run.return_value = _completed(
            stderr="ff:ff:ff:ff:ff:ff > aa:bb:cc:dd:ee:ff"
        )
        nac = _make_nac()
        nac.implant_mac = "aa:bb:cc:dd:ee:ff"
        result = nac._discover_downstream_mac()
        self.assertIsNone(result)

    @patch("software.nac_bypass._run")
    def test_discovery_skips_own_mac(self, mock_run):
        mock_run.return_value = _completed(
            stderr="aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66"
        )
        nac = _make_nac()
        nac.implant_mac = "aa:bb:cc:dd:ee:ff"
        result = nac._discover_downstream_mac()
        self.assertEqual(result, "11:22:33:44:55:66")

    @patch("software.nac_bypass._run")
    def test_discovery_returns_victim_mac(self, mock_run):
        mock_run.return_value = _completed(
            stderr="de:ad:be:ef:ca:fe > aa:bb:cc:dd:ee:ff, IPv4"
        )
        nac = _make_nac()
        nac.implant_mac = "aa:bb:cc:dd:ee:ff"
        result = nac._discover_downstream_mac()
        self.assertEqual(result, "de:ad:be:ef:ca:fe")

    @patch("software.nac_bypass._run")
    def test_arp_discovery_parses_victim_ip_from_request(self, mock_run):
        # Victim sends ARP request — victim MAC as src, broadcast as dst
        arp_output = (
            "11:22:33:44:55:66 > ff:ff:ff:ff:ff:ff, ARP, "
            "Request who-has 10.0.0.1 tell 10.0.0.42\n"
        )
        mock_run.return_value = _completed(stderr=arp_output)
        nac = _make_nac()
        nac.victim_mac = "11:22:33:44:55:66"
        nac.implant_mac = "00:00:00:00:00:01"

        _, _, victim_ip = nac._discover_via_arp()
        self.assertEqual(victim_ip, "10.0.0.42")

    @patch("software.nac_bypass._run")
    def test_arp_discovery_parses_gateway_from_different_src(self, mock_run):
        # Gateway sends ARP request from its own MAC (not to victim MAC)
        arp_output = (
            "aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ARP, "
            "Request who-has 10.0.0.42 tell 10.0.0.1\n"
        )
        mock_run.return_value = _completed(stderr=arp_output)
        nac = _make_nac()
        nac.victim_mac = "11:22:33:44:55:66"
        nac.implant_mac = "00:00:00:00:00:01"

        gw_mac, gw_ip, _ = nac._discover_via_arp()
        self.assertEqual(gw_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(gw_ip, "10.0.0.42")

    @patch("software.nac_bypass._run")
    def test_arp_discovery_combined(self, mock_run):
        # Two separate ARP exchanges — victim request + gateway request
        arp_output = (
            "11:22:33:44:55:66 > ff:ff:ff:ff:ff:ff, ARP, "
            "Request who-has 10.0.0.1 tell 10.0.0.42\n"
            "aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ARP, "
            "Request who-has 10.0.0.42 tell 10.0.0.1\n"
        )
        mock_run.return_value = _completed(stderr=arp_output)
        nac = _make_nac()
        nac.victim_mac = "11:22:33:44:55:66"
        nac.implant_mac = "00:00:00:00:00:01"

        gw_mac, gw_ip, victim_ip = nac._discover_via_arp()
        self.assertEqual(victim_ip, "10.0.0.42")
        self.assertEqual(gw_mac, "aa:bb:cc:dd:ee:ff")

    @patch("software.nac_bypass._run")
    def test_arp_discovery_victim_ip_overwritten_by_reply(self, mock_run):
        """Known limitation: if victim MAC appears as dst in a gateway ARP
        reply, the victim_ip gets overwritten with the gateway's IP because
        the code doesn't distinguish src vs dst MAC position."""
        arp_output = (
            "11:22:33:44:55:66 > ff:ff:ff:ff:ff:ff, ARP, "
            "Request who-has 10.0.0.1 tell 10.0.0.42\n"
            "aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ARP, "
            "Reply 10.0.0.1 is-at aa:bb:cc:dd:ee:ff\n"
        )
        mock_run.return_value = _completed(stderr=arp_output)
        nac = _make_nac()
        nac.victim_mac = "11:22:33:44:55:66"
        nac.implant_mac = "00:00:00:00:00:01"

        _, _, victim_ip = nac._discover_via_arp()
        # Bug: victim_ip is overwritten to gateway IP because victim MAC
        # appears as dst in line 2 and ips_in_line[-1] = "10.0.0.1"
        self.assertEqual(victim_ip, "10.0.0.1")


class TestSilentPhase(unittest.TestCase):
    @patch("software.nac_bypass._run_quiet")
    def test_go_silent_drops_output_on_both_interfaces(self, mock_rq):
        nac = _make_nac()
        nac._go_silent()

        expected = [
            call("arptables -A OUTPUT -o eth0 -j DROP"),
            call("arptables -A OUTPUT -o eth1 -j DROP"),
            call("iptables -A OUTPUT -o eth0 -j DROP"),
            call("iptables -A OUTPUT -o eth1 -j DROP"),
        ]
        mock_rq.assert_has_calls(expected, any_order=False)

    @patch("software.nac_bypass._run_quiet")
    def test_go_live_removes_drop_rules(self, mock_rq):
        nac = _make_nac()
        nac._go_live()

        expected = [
            call("arptables -D OUTPUT -o eth0 -j DROP"),
            call("arptables -D OUTPUT -o eth1 -j DROP"),
            call("iptables -D OUTPUT -o eth0 -j DROP"),
            call("iptables -D OUTPUT -o eth1 -j DROP"),
        ]
        mock_rq.assert_has_calls(expected, any_order=False)


class TestPhase3RewriteRules(unittest.TestCase):
    def _setup_nac(self):
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.victim_ip = "10.0.0.42"
        nac.gateway_mac = "aa:bb:cc:dd:ee:ff"
        nac.gateway_ip = "10.0.0.1"
        nac.implant_mac = "00:11:22:33:44:55"
        return nac

    @patch("software.nac_bypass._run_quiet")
    def test_silent_before_rules_live_after(self, mock_rq):
        """Verify go_silent is called first and go_live is called last."""
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        calls = [str(c) for c in mock_rq.call_args_list]

        # First 4 calls must be the silent DROP rules
        self.assertIn("arptables -A OUTPUT -o eth0 -j DROP", calls[0])

        # Last 4 calls must be the live -D rules
        self.assertIn("arptables -D OUTPUT -o eth0 -j DROP", calls[-4])

    @patch("software.nac_bypass._run_quiet")
    def test_bridge_nf_call_iptables_enabled(self, mock_rq):
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call("sysctl -w net.bridge.bridge-nf-call-iptables=1")

    @patch("software.nac_bypass._run_quiet")
    def test_bridge_nf_before_iptables_rules(self, mock_rq):
        """bridge-nf-call-iptables=1 must come before any iptables SNAT rule."""
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        cmds = [c[0][0] for c in mock_rq.call_args_list]
        sysctl_idx = cmds.index("sysctl -w net.bridge.bridge-nf-call-iptables=1")
        first_iptables = next(
            i for i, c in enumerate(cmds) if "iptables -t nat" in c
        )
        self.assertLess(sysctl_idx, first_iptables)

    @patch("software.nac_bypass._run_quiet")
    def test_ebtables_snat_on_upstream_and_bridge(self, mock_rq):
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call(
            "ebtables -t nat -A POSTROUTING -s 00:11:22:33:44:55 "
            "-o eth0 -j snat --to-source de:ad:be:ef:00:01"
        )
        mock_rq.assert_any_call(
            "ebtables -t nat -A POSTROUTING -s 00:11:22:33:44:55 "
            "-o br0 -j snat --to-source de:ad:be:ef:00:01"
        )

    @patch("software.nac_bypass._run_quiet")
    def test_ebtables_dnat_for_incoming(self, mock_rq):
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call(
            "ebtables -t nat -A PREROUTING -i eth0 "
            "-s aa:bb:cc:dd:ee:ff -d de:ad:be:ef:00:01 "
            "-j dnat --to-destination 00:11:22:33:44:55"
        )

    @patch("software.nac_bypass._run_quiet")
    def test_iptables_snat_with_port_range(self, mock_rq):
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call(
            "iptables -t nat -A POSTROUTING -o br0 "
            "-p tcp -j SNAT --to 10.0.0.42:61000-62000"
        )
        mock_rq.assert_any_call(
            "iptables -t nat -A POSTROUTING -o br0 "
            "-p udp -j SNAT --to 10.0.0.42:61000-62000"
        )
        mock_rq.assert_any_call(
            "iptables -t nat -A POSTROUTING -o br0 "
            "-p icmp -j SNAT --to 10.0.0.42"
        )

    @patch("software.nac_bypass._run_quiet")
    def test_custom_port_range(self, mock_rq):
        nac = _make_nac(nat_port_range="50000-51000")
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.victim_ip = "10.0.0.42"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call(
            "iptables -t nat -A POSTROUTING -o br0 "
            "-p tcp -j SNAT --to 10.0.0.42:50000-51000"
        )

    @patch("software.nac_bypass._run_quiet")
    def test_arptables_mangle_rules(self, mock_rq):
        nac = self._setup_nac()
        nac.apply_rewrite_rules()

        mock_rq.assert_any_call(
            "arptables -A OUTPUT -o br0 "
            "--opcode request -j mangle --mangle-mac-s de:ad:be:ef:00:01"
        )
        mock_rq.assert_any_call(
            "arptables -A OUTPUT -o br0 "
            "--opcode reply -j mangle --mangle-mac-s de:ad:be:ef:00:01"
        )

    @patch("software.nac_bypass._run_quiet")
    def test_no_rules_without_victim_mac(self, mock_rq):
        nac = _make_nac()
        nac.victim_mac = None
        nac.apply_rewrite_rules()
        mock_rq.assert_not_called()

    @patch("software.nac_bypass._run_quiet")
    def test_no_dnat_without_gateway_mac(self, mock_rq):
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.gateway_mac = None
        nac.apply_rewrite_rules()

        dnat_calls = [
            c for c in mock_rq.call_args_list
            if "PREROUTING" in str(c)
        ]
        self.assertEqual(len(dnat_calls), 0)

    @patch("software.nac_bypass._run_quiet")
    def test_no_iptables_without_victim_ip(self, mock_rq):
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.victim_ip = None
        nac.apply_rewrite_rules()

        iptables_snat = [
            c for c in mock_rq.call_args_list
            if "iptables -t nat -A POSTROUTING" in str(c)
        ]
        self.assertEqual(len(iptables_snat), 0)


class TestPhase3RuleOrder(unittest.TestCase):
    """Verify the exact order: silent → sysctl → MAC spoof → ebtables → iptables → arptables → live."""

    @patch("software.nac_bypass._run_quiet")
    def test_full_rule_order(self, mock_rq):
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.victim_ip = "10.0.0.42"
        nac.gateway_mac = "aa:bb:cc:dd:ee:ff"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.apply_rewrite_rules()

        cmds = [c[0][0] for c in mock_rq.call_args_list]

        # Find indices of key operations
        def idx_of(substr):
            return next(i for i, c in enumerate(cmds) if substr in c)

        silent_start = idx_of("arptables -A OUTPUT -o eth0 -j DROP")
        sysctl = idx_of("bridge-nf-call-iptables=1")
        mac_spoof = idx_of("ip link set dev br0 address")
        ebtables_nat = idx_of("ebtables -t nat -A POSTROUTING")
        iptables_snat = idx_of("iptables -t nat -A POSTROUTING")
        arptables_mangle = idx_of("arptables -A OUTPUT -o br0")
        live_start = idx_of("arptables -D OUTPUT -o eth0 -j DROP")

        self.assertLess(silent_start, sysctl)
        self.assertLess(sysctl, mac_spoof)
        self.assertLess(mac_spoof, ebtables_nat)
        self.assertLess(ebtables_nat, iptables_snat)
        self.assertLess(iptables_snat, arptables_mangle)
        self.assertLess(arptables_mangle, live_start)


class TestTeardown(unittest.TestCase):
    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_restores_bridge_nf(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()

        mock_rq.assert_any_call("sysctl -w net.bridge.bridge-nf-call-iptables=0")

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_flushes_nat_not_filter(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()

        mock_rq.assert_any_call("ebtables -t nat -F")
        mock_rq.assert_any_call("iptables -t nat -F")

        filter_flush_calls = [
            c for c in mock_rq.call_args_list
            if "ebtables -t filter -F" in str(c)
        ]
        self.assertEqual(len(filter_flush_calls), 0)

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_removes_arptables_mangle_specifically(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()

        mock_rq.assert_any_call(
            "arptables -D OUTPUT -o br0 "
            "--opcode request -j mangle --mangle-mac-s de:ad:be:ef:00:01"
        )
        mock_rq.assert_any_call(
            "arptables -D OUTPUT -o br0 "
            "--opcode reply -j mangle --mangle-mac-s de:ad:be:ef:00:01"
        )

        arptables_flush = [
            c for c in mock_rq.call_args_list
            if c[0][0] == "arptables -F"
        ]
        self.assertEqual(len(arptables_flush), 0)

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_restores_original_mac(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()

        mock_rq.assert_any_call("ip link set dev br0 address 00:11:22:33:44:55")

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_re_enables_eapol(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()

        eapol_accept = [
            c for c in mock_run.call_args_list
            if "ebtables -t filter -A FORWARD -d 01:80:c2:00:00:03 -j ACCEPT" in str(c)
        ]
        self.assertGreater(len(eapol_accept), 0)

    @patch("software.nac_bypass._run")
    @patch("software.nac_bypass._run_quiet")
    @patch("builtins.open", mock_open())
    def test_stop_sets_phase_idle(self, mock_rq, mock_run):
        mock_run.return_value = _completed()
        nac = _make_nac()
        nac.victim_mac = "de:ad:be:ef:00:01"
        nac.implant_mac = "00:11:22:33:44:55"
        nac.stop()
        self.assertEqual(nac._phase, "idle")


class TestConfigureNetwork(unittest.TestCase):
    @patch("software.nac_bypass._run_quiet")
    def test_static_ip_when_both_known(self, mock_rq):
        nac = _make_nac()
        nac.victim_ip = "10.0.0.42"
        nac.gateway_ip = "10.0.0.1"
        nac.configure_network()

        mock_rq.assert_any_call("ip addr add 10.0.0.42/24 dev br0")
        mock_rq.assert_any_call("ip route add default via 10.0.0.1 dev br0")

    @patch("software.nac_bypass._run_quiet")
    def test_dhcp_fallback(self, mock_rq):
        nac = _make_nac()
        nac.victim_ip = None
        nac.gateway_ip = None
        nac.configure_network()

        mock_rq.assert_any_call("dhclient -nw br0")


class TestStopCanActuallyStopIt(unittest.TestCase):
    """`stop()` sets a flag, and the sequence has to read it.

    It did not. `start()` spawns a thread; `_run_sequence` forwards
    EAPOL, sleeps, and then discovers the downstream host with a tcpdump
    that runs for up to a minute **after** the MAC is known -- and then
    applied the rewrite rules whatever had happened in between. So a
    caller that stopped the bypass during discovery had the rules
    applied afterwards anyway, on the identity it had just refused.

    The way out's rung 4 restore is that caller: it refuses a host the
    arithmetic never priced, logs "nac_bypass has been stopped", and
    calls `stop()`. Driven with the real sequence here rather than a fake
    whose `stop()` appends to a list, because "stop was called" is a fact
    about this process and "the MAC did not move" is a fact about the
    kernel.
    """

    def driven(self, nac, ran, stop_during_capture=False):
        """Replace only the shell, and record every command."""
        def run_quiet(command, *_args, **_kwargs):
            ran.append(command)
            return _completed()

        def run(command, *_args, **_kwargs):
            ran.append(command)
            if stop_during_capture and "tcpdump" in command:
                # What the caller does while the capture is running: the
                # MAC is about to be known and the identity refused.
                nac._running = False
            # Enough for `_discover_via_arp` to learn a victim and a
            # gateway from one capture.
            if "tcpdump" in command:
                return _completed(stdout=(
                    "aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, "
                    "Request who-has 10.0.0.254 tell 10.0.0.9\n"
                    "11:22:33:44:55:66 > aa:bb:cc:dd:ee:ff, "
                    "Reply 10.0.0.254 is-at 11:22:33:44:55:66\n"))
            return _completed()

        return (patch("software.nac_bypass._run_quiet", run_quiet),
                patch("software.nac_bypass._run", run),
                patch("software.nac_bypass.time.sleep", lambda _s: None))

    def test_a_stop_during_discovery_leaves_the_mac_where_it_was(self):
        # The sharp case, and the one the way out's rung 4 restore
        # creates: the sequence is *inside* its capture when the caller
        # refuses the identity, so discovery completes and learns a MAC
        # either way. What may not happen is the rules going in.
        nac = _make_nac()
        ran = []
        patchers = self.driven(nac, ran, stop_during_capture=True)
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        nac._running = True
        nac._run_sequence()

        self.assertTrue([command for command in ran if "tcpdump" in command],
                        "discovery never ran, so this test is not about the "
                        "check after it")
        self.assertEqual(nac.victim_mac, "aa:bb:cc:dd:ee:ff",
                         "the MAC was not learned, so there was nothing to "
                         "refuse")
        moved = [command for command in ran
                 if "link set dev br0 address" in command]
        self.assertEqual(moved, [],
                         "the bridge's MAC was changed after the caller "
                         "stopped the bypass: %r" % (ran,))
        self.assertEqual([command for command in ran if "snat" in command],
                         [])
        self.assertNotEqual(nac._phase, "active")

    def test_a_stop_before_discovery_does_not_even_capture(self):
        # The cheaper check, and a separate one: a bypass stopped while
        # it was still waiting out the host's 802.1X exchange should not
        # spend a minute of tcpdump on a port it has been told to leave
        # alone.
        nac = _make_nac()
        ran = []
        patchers = self.driven(nac, ran)
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        nac._running = False
        nac._run_sequence()

        self.assertEqual([command for command in ran if "tcpdump" in command],
                         [], "discovery ran after the bypass was stopped")
        self.assertIsNone(nac.victim_mac)

    def test_a_sequence_nobody_stopped_still_applies_its_rules(self):
        # The other half, so the guard cannot be "do nothing ever".
        nac = _make_nac()
        ran = []
        patchers = self.driven(nac, ran)
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        nac._running = True
        nac._run_sequence()

        self.assertTrue([command for command in ran
                         if "link set dev br0 address" in command],
                        "the sequence took nothing at all: %r" % (ran,))
        self.assertEqual(nac._phase, "active")


class TestStatus(unittest.TestCase):
    def test_status_returns_all_fields(self):
        nac = _make_nac()
        nac.victim_mac = "aa:bb:cc:dd:ee:ff"
        nac.victim_ip = "10.0.0.1"
        nac.gateway_mac = "11:22:33:44:55:66"
        nac.gateway_ip = "10.0.0.254"
        nac._phase = "active"

        s = nac.status
        self.assertEqual(s["phase"], "active")
        self.assertEqual(s["victim_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(s["victim_ip"], "10.0.0.1")
        self.assertEqual(s["gateway_mac"], "11:22:33:44:55:66")
        self.assertEqual(s["gateway_ip"], "10.0.0.254")


if __name__ == "__main__":
    unittest.main()

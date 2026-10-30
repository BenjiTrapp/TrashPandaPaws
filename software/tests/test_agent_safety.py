#!/usr/bin/env python3
"""
Tests for the agent safety layer: shell metacharacter screening, the three-tier
classifier (classified by effect, not by program name), scan-limit injection,
stored-script validation and the LLM probability clamp.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from software.agent import safety


def _classify(cmd, **kw):
    kw.setdefault("target_kind", "beacon")
    kw.setdefault("is_uplink_iface", lambda n: n == "eth0")
    kw.setdefault("phase5_enabled", True)
    return safety.classify(cmd, **kw)


class TestMetachars(unittest.TestCase):
    def test_rejects_each_metacharacter(self):
        for bad in ("ls; rm -rf /", "a | b", "a && b", "a `id`", "a $(id)",
                    "a > f", "a\nb", "a & b"):
            self.assertTrue(safety.has_shell_metachars(bad), bad)

    def test_accepts_plain_command_with_flags(self):
        self.assertFalse(safety.has_shell_metachars("nmap -sV -p 445 10.0.1.5"))

    def test_rejects_further_shell_syntax(self):
        for bad in ("a < f", "a ${IFS} b", "(reboot)", "a\rb", "a\x00b"):
            self.assertTrue(safety.has_shell_metachars(bad), repr(bad))


class TestTierOne(unittest.TestCase):
    def _c(self, cmd, **kw):
        return _classify(cmd, **kw)

    def test_beacon_control_is_hard_blocked(self):
        for cmd in ("kill", "unpersist auto", "reconfig"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_HARD, cmd)

    def test_long_sleep_is_hard_blocked(self):
        self.assertEqual(self._c("sleep 7200 20").tier, safety.TIER_HARD)
        self.assertNotEqual(self._c("sleep 15 20").tier, safety.TIER_HARD)

    def test_network_config_on_beacon_host_is_hard_blocked(self):
        for cmd in ("shell ip link set eth0 down", "shell nmcli radio off",
                    "shell iptables -F", "shell systemctl restart NetworkManager"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_HARD, cmd)

    def test_reboot_and_shutdown_are_hard_blocked(self):
        for cmd in ("shell reboot", "shell /sbin/shutdown -h now",
                    "shell sudo poweroff"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_HARD, cmd)

    def test_dropbox_lifelines_are_hard_blocked(self):
        for cmd in ("shell pkill -f bridge_tap.py", "shell brctl delif br0 eth1",
                    "shell systemctl stop raccoon-nac"):
            self.assertEqual(
                self._c(cmd, target_kind="dropbox").tier, safety.TIER_HARD, cmd)

    def test_monitor_mode_on_uplink_is_hard_blocked(self):
        self.assertEqual(
            self._c("shell iw dev eth0 set type monitor").tier, safety.TIER_HARD)

    def test_airmon_check_kill_is_hard_blocked_with_and_without_sudo(self):
        for cmd in ("shell airmon-ng check kill", "shell sudo airmon-ng check kill"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_HARD, cmd)

    def test_path_prefixed_binary_is_still_caught(self):
        self.assertEqual(self._c("shell /sbin/reboot").tier, safety.TIER_HARD)

    def test_exploitation_blocked_when_phase5_disabled(self):
        cmd = "shell msfconsole -q -x 'use exploit/windows/smb/ms17_010'"
        self.assertEqual(self._c(cmd, phase5_enabled=False).tier, safety.TIER_HARD)
        self.assertEqual(self._c(cmd, phase5_enabled=True).tier, safety.TIER_KNOCK)


class TestTierOneSpellings(unittest.TestCase):
    """The second obvious way to ask for each tier-1 effect."""

    def _hard(self, cmds, **kw):
        for cmd in cmds:
            self.assertEqual(_classify(cmd, **kw).tier, safety.TIER_HARD, cmd)

    def test_power_off_every_spelling(self):
        self._hard(("shell halt", "shell init 0", "shell telinit 6",
                    "shell systemctl poweroff", "shell sudo -n systemctl reboot",
                    "shell sudo -u root /usr/sbin/reboot", "shell doas reboot",
                    "shell sh -c 'reboot'", "shell shutdown -r now",
                    "shell /SBIN/REBOOT", "shell   sudo    reboot"))

    def test_quote_and_backslash_tricks_do_not_hide_the_verb(self):
        self._hard(("shell re''boot", 'shell "reboot"', "shell r\\eboot",
                    "shell C:\\Windows\\System32\\shutdown.exe /s"))

    def test_reboot_as_a_filename_is_not_a_reboot(self):
        self.assertNotEqual(
            _classify("shell cat /var/log/reboot.log").tier, safety.TIER_HARD)

    def test_firewall_changes_through_every_tool(self):
        self._hard(("shell iptables -t nat -F", "shell ip6tables --flush",
                    "shell iptables -P INPUT DROP", "shell nft flush ruleset",
                    "shell ufw enable", "shell ufw reset",
                    "shell firewall-cmd --reload", "shell ebtables -F"))

    def test_firewall_listing_is_not_blocked(self):
        for cmd in ("shell iptables -L -n", "shell iptables -t nat -L -v",
                    "shell nft list ruleset", "shell ufw status"):
            self.assertNotEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def test_network_services_every_spelling(self):
        self._hard(("shell systemctl stop NetworkManager",
                    "shell service networking restart",
                    "shell systemctl restart systemd-networkd",
                    "shell systemctl disable wpa_supplicant",
                    "shell /etc/init.d/networking restart", "shell netplan apply",
                    "shell nmcli networking off", "shell nmcli r all off",
                    "shell nmcli connection down id corp",
                    "shell ip route flush all", "shell ip route del default",
                    "shell ip -4 addr flush dev eth0", "shell dhclient -r"))

    def test_uplink_interface_down_every_spelling(self):
        self._hard(("shell ip link set dev eth0 down", "shell ip link set down dev eth0",
                    "shell ifconfig eth0 down", "shell ifdown eth0",
                    "shell nmcli device disconnect eth0", "shell ip link delete eth0",
                    "shell iwconfig eth0 mode monitor",
                    "shell airmon-ng start eth0", "shell iw eth0 set monitor none"))

    def test_non_uplink_interface_down_is_not_hard(self):
        self.assertNotEqual(
            _classify("shell ip link set wlan1 down").tier, safety.TIER_HARD)

    def test_unknown_uplink_refuses_every_interface_mode_change(self):
        for cmd in ("shell iw dev wlan1 set type monitor",
                    "shell ip link set wlan1 down", "shell ifconfig wlan1 down"):
            self.assertEqual(
                _classify(cmd, is_uplink_iface=lambda n: True).tier,
                safety.TIER_HARD, cmd)

    def test_failing_uplink_callable_fails_closed(self):
        def broken(name):
            raise RuntimeError("no idea")
        self.assertEqual(
            _classify("shell ip link set wlan1 down", is_uplink_iface=broken).tier,
            safety.TIER_HARD)

    def test_beacon_verbs_hard_whatever_the_arguments(self):
        self._hard(("kill now", "reconfig {}", "unpersist crontab", "sudo kill",
                    "KILL", "  kill  "))

    def test_sleep_hostile_arguments_are_hard(self):
        self._hard(("sleep 3600", "sleep 99999 0", "sleep inf", "sleep 1e9",
                    "sleep 0007200", "sleep nan 5", "sleep"))

    def test_sleep_reasonable_values_pass(self):
        for cmd in ("sleep 15 20", "sleep 300", "sleep 3599", "sleep 0.5", "sleep 1"):
            self.assertNotEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def test_airmon_check_kill_abbreviated_and_spaced(self):
        self._hard(("shell airmon-ng   check   kill", "shell /usr/sbin/airmon-ng check kill",
                    "shell sudo -E airmon-ng check kill"))

    def test_lifelines_every_spelling_on_dropbox(self):
        self._hard(("shell killall python3", "shell pkill -9 -f raccoon",
                    "shell pkill sshd", "shell kill -9 -1",
                    "shell systemctl restart raccoon-bridge.service",
                    "shell systemctl disable --now raccoon-beacon",
                    "shell systemctl mask raccoon-watchdog",
                    "shell service raccoon-implant stop",
                    "shell /etc/init.d/raccoon-nac stop",
                    "shell systemctl stop ssh", "shell systemctl stop autossh",
                    "shell brctl delbr br0", "shell brctl stp br0 on",
                    "shell ip link set eth1 nomaster", "shell ip link delete br0",
                    "shell ip link set br0 down", "shell bridge fdb flush dev br0",
                    "shell rm -rf /opt/raccoon", "shell rm /opt/raccoon/bin/implant",
                    "shell mv /opt/raccoon /tmp/x", "shell shred /etc/systemd/system/raccoon-beacon.service",
                    "rm -f /opt/raccoon/config/raccoon.yaml", "shell unlink bridge_tap.py"),
                   target_kind="dropbox")

    def test_lifeline_rules_apply_only_to_dropbox(self):
        for cmd in ("shell pkill -f bridge_tap.py", "shell brctl delif br0 eth1",
                    "shell systemctl stop raccoon-nac", "shell rm -rf /opt/raccoon"):
            for kind in ("beacon", "server"):
                self.assertNotEqual(
                    _classify(cmd, target_kind=kind).tier, safety.TIER_HARD,
                    "%s on %s" % (cmd, kind))

    def test_lifeline_status_and_listing_are_not_blocked(self):
        for cmd in ("shell systemctl status raccoon-beacon", "shell brctl show",
                    "shell ls /opt/raccoon", "shell cat /opt/raccoon/config/raccoon.yaml",
                    "shell journalctl -u raccoon-beacon"):
            self.assertNotEqual(
                _classify(cmd, target_kind="dropbox").tier, safety.TIER_HARD, cmd)

    def test_disk_and_system_wipe_is_hard(self):
        self._hard(("shell rm -rf /", "shell rm -rf /*", "shell rm -fr /etc",
                    "shell rm --recursive --no-preserve-root /", "shell mkfs.ext4 /dev/sda1",
                    "shell dd if=/dev/zero of=/dev/mmcblk0", "shell wipefs -a /dev/sda"))

    def test_scoped_rm_is_not_a_wipe(self):
        self.assertNotEqual(_classify("shell rm -rf /tmp/work").tier, safety.TIER_HARD)

    def test_exploit_spellings_follow_the_phase5_switch(self):
        for cmd in ("shell msfconsole -r pwn.rc", "shell nmap --script=exploit 10.0.1.5",
                    "shell nmap --script smb-vuln-ms17-010,dos 10.0.1.5",
                    "shell python3 exploit.py 10.0.1.5", "shell routersploit"):
            self.assertEqual(
                _classify(cmd, phase5_enabled=False).tier, safety.TIER_HARD, cmd)
            self.assertEqual(
                _classify(cmd, phase5_enabled=True).tier, safety.TIER_KNOCK, cmd)

    def test_tier_one_wins_over_tier_two_in_a_mixed_line(self):
        self.assertEqual(
            _classify("responder -I eth0 reboot").tier, safety.TIER_HARD)
        self.assertEqual(
            _classify("reboot responder -I eth0").tier, safety.TIER_HARD)

    def test_chained_hard_command_is_not_hidden_by_a_free_prefix(self):
        self.assertEqual(
            _classify("ls /tmp; iptables -F").tier, safety.TIER_HARD)

    def test_spellings_found_by_adversarial_review(self):
        """Gaps the first pass missed; each is a second way to ask."""
        self._hard(("shell systemctl kexec", "shell kexec -e",
                    "shell nmcli networking disable",
                    "shell nmcli radio all disable"))
        # Zeroing the uplink address strands the beacon as surely as `down`.
        self._hard(("shell ifconfig eth0 0.0.0.0",))
        self.assertNotEqual(
            _classify("shell ifconfig wlan1 0.0.0.0").tier, safety.TIER_HARD)


class TestTierTwoClassifiesByEffect(unittest.TestCase):
    """Review Focus 2: Wirkung zählt, nicht der Binärname."""
    def _c(self, cmd):
        return safety.classify(cmd, target_kind="server",
                               is_uplink_iface=lambda n: False, phase5_enabled=True)

    def test_lsass_dump_via_any_tool_knocks(self):
        for cmd in ("lsassy -d corp -u a -p b 10.0.1.5",
                    "nxc smb 10.0.1.5 -u a -p b -M lsassy",
                    "impacket-secretsdump a:b@10.0.1.5",
                    "shell procdump -ma lsass.exe out.dmp"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_KNOCK, cmd)

    def test_responder_and_coercion_knock(self):
        for cmd in ("python3 /opt/Responder/Responder.py -I eth0 -w",
                    "ntlmrelayx.py -t ldap://10.0.1.1",
                    "petitpotam.py 10.0.1.9 10.0.1.1"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_KNOCK, cmd)

    def test_log_clearing_and_shadow_copy_deletion_knock(self):
        for cmd in ("shell wevtutil cl Security",
                    "shell vssadmin delete shadows /all /quiet",
                    "shell wmic shadowcopy delete"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_KNOCK, cmd)

    def test_persist_knocks_but_unpersist_is_hard_blocked(self):
        self.assertEqual(self._c("persist crontab").tier, safety.TIER_KNOCK)
        self.assertEqual(
            safety.classify("unpersist crontab", target_kind="beacon",
                            is_uplink_iface=lambda n: False,
                            phase5_enabled=True).tier, safety.TIER_HARD)

    def test_recon_stays_free(self):
        for cmd in ("nmap -sV 10.0.1.5", "ls /tmp", "whoami", "netscan 10.0.1.0/24"):
            self.assertEqual(self._c(cmd).tier, safety.TIER_FREE, cmd)

    # ── Additional spellings of the same effects ──

    def _assert_action(self, cmds, action_key):
        for cmd in cmds:
            got = self._c(cmd)
            self.assertEqual((got.tier, got.action_key),
                             (safety.TIER_KNOCK, action_key), cmd)

    def test_credential_dumping_every_spelling(self):
        self._assert_action((
            "mimikatz sekurlsa::logonpasswords", "pypykatz lsa minidump out.dmp",
            "shell rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 o.dmp full",
            "shell reg save HKLM\\SAM sam.hive", "shell ntdsutil \"ac i ntds\" ifm",
            "nxc smb 10.0.1.5 -u a -p b --lsa", "nxc smb 10.0.1.5 -u a -p b --ntds",
            "crackmapexec smb 10.0.1.5 -u a -p b --sam",
            "nxc smb 10.0.1.5 -u a -p b -M nanodump",
            "secretsdump.py a:b@10.0.1.5", "shell nanodump.exe --write o.dmp",
            "shell copy C:\\Windows\\NTDS\\ntds.dit x"), "lsass_dump")

    def test_poisoning_and_relay_every_spelling(self):
        self._assert_action(("responder -I eth0", "Responder.py -I eth0 -A",
                             "inveigh", "mitm6 -d corp.local"), "responder")
        self._assert_action(("impacket-ntlmrelayx -t smb://10.0.1.5",
                             "krbrelayx.py", "smbrelayx.py",
                             "printerbug.py corp/a@10.0.1.9 10.0.1.2",
                             "dfscoerce.py", "coercer coerce -t 10.0.1.9",
                             "nxc smb 10.0.1.9 -M coerce_plus",
                             "PetitPotam.py 1 2"), "ntlm_relay")

    def test_log_clearing_every_spelling(self):
        self._assert_action((
            "shell wevtutil clear-log Security", "shell wevtutil.exe cl System",
            "shell powershell Clear-EventLog -LogName Security",
            "shell journalctl --vacuum-time=1s", "shell rm /var/log/auth.log",
            "shell shred -u /var/log/syslog", "shell truncate -s 0 /var/log/wtmp",
            "shell history -c", "shell rm ~/.bash_history"), "log_clear")

    def test_shadow_copy_deletion_every_spelling(self):
        self._assert_action((
            "shell vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401mb",
            "shell wbadmin delete catalog -quiet",
            "shell bcdedit /set {default} recoveryenabled no",
            "shell powershell Get-WmiObject Win32_ShadowCopy | Remove-WmiObject".replace("|", ""),
            "shell diskshadow /s s.txt"), "shadow_copy_delete")

    def test_persistence_every_spelling(self):
        self._assert_action((
            "shell crontab -e", "shell crontab mycron", "shell systemctl enable evil",
            "shell schtasks /create /tn x /tr c:\\x.exe /sc onlogon",
            "shell reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x",
            "shell sc create evil binpath= c:\\x.exe", "shell useradd -m backdoor",
            "shell net user backdoor P@ss /add", "shell launchctl load x.plist",
            "shell tee -a /home/u/.ssh/authorized_keys", "shell cp x /etc/rc.local",
            "write /home/u/.bashrc"), "persist")

    def test_crontab_listing_is_free(self):
        self.assertEqual(self._c("shell crontab -l").tier, safety.TIER_FREE)

    def test_at_scheduler_is_persistence(self):
        """The pre-schtasks spelling, found by adversarial review."""
        self._assert_action(("shell at 09:00 /f c:\\x.exe",
                             "shell at 23:30 /interactive c:\\x.exe"), "persist")

    def test_deauth_every_spelling(self):
        self._assert_action(("shell aireplay-ng -0 5 -a aa:bb wlan0mon",
                             "shell aireplay-ng --deauth 10 wlan0mon",
                             "shell mdk4 wlan0mon d", "shell besside-ng wlan0mon",
                             "shell bettercap -eval 'wifi.deauth *'"), "deauth")

    def test_hit_carries_risk_table_values(self):
        got = self._c("persist crontab")
        self.assertEqual(got, safety.RISK_TABLE["persist"])
        self.assertEqual(got.action_key, "persist")

    def test_unknown_tier_two_action_gets_conservative_prior(self):
        added = (safety.re.compile(r"\bfrobnicate\b"), "frobnicate")
        safety._RULES.append(added)
        try:
            got = self._c("frobnicate the thing")
        finally:
            safety._RULES.remove(added)
        # an unlisted key has no tier of its own; it must never become tier 3
        self.assertEqual((got.tier, got.points, got.p_success, got.p_detect),
                         (safety.TIER_KNOCK, 25, 0.3, 0.6))

    def test_risk_table_contains_required_rows(self):
        for key in ("lsass_dump", "responder", "ntlm_relay", "persist", "deauth",
                    "exploit_known_poc"):
            row = safety.RISK_TABLE[key]
            self.assertEqual(row.tier, safety.TIER_KNOCK, key)
            self.assertEqual(row.action_key, key)
            self.assertTrue(row.action_class and row.reason, key)
            self.assertGreater(row.points, 0, key)
            self.assertTrue(0 < row.p_success < 1 and 0 < row.p_detect < 1, key)

    def test_every_rule_key_is_in_the_risk_table_with_a_matching_tier(self):
        for _pattern, key in safety._RULES:
            self.assertIn(key, safety.RISK_TABLE, key)
            self.assertEqual(safety.RISK_TABLE[key].action_key, key)
            self.assertIn(safety.RISK_TABLE[key].tier,
                          (safety.TIER_HARD, safety.TIER_KNOCK), key)

    def test_free_command_reports_free_classification(self):
        got = self._c("whoami")
        self.assertEqual(got.tier, safety.TIER_FREE)
        self.assertEqual(got.points, 0)


class TestReviewFindings(unittest.TestCase):
    """Spellings the task review found reaching the wrong tier.

    Each of these returned TIER_FREE before the fix round. They are pinned
    here because a guardrail that catches only the spelling its author
    thought of first provides false assurance.
    """

    def _hard(self, cmds, **kw):
        for cmd in cmds:
            self.assertEqual(_classify(cmd, **kw).tier, safety.TIER_HARD, cmd)

    def test_the_root_wipe_that_actually_works(self):
        """GNU rm refuses a bare `/`; the trailing-flag form is the real one."""
        self._hard(("shell rm -rf / --no-preserve-root",
                    "shell rm -rf /etc /var", "shell rm -rf ~",
                    "shell rm -fr /home --verbose"))

    def test_raw_device_writes(self):
        self._hard(("shell shred /dev/sda", "shell dd of=/dev/sda bs=4m",
                    "shell rm /dev/sda1", "shell parted /dev/sda mklabel gpt"))

    def test_windows_and_target_switch_power_off(self):
        self._hard(("shell powershell restart-computer -force",
                    "shell stop-computer -force",
                    "shell systemctl isolate rescue.target",
                    "shell systemctl emergency"))

    def test_path_and_wrapper_prefixed_beacon_verbs(self):
        """A wrapper or absolute path must not hide the verb."""
        self._hard(("shell /usr/bin/sleep 7200", "shell nohup sleep 7200",
                    "shell timeout 5 sleep 7200", "shell /bin/kill 1234",
                    "env reconfig", "shell sudo -u alice sleep 7200",
                    "shell setsid unpersist auto"))

    def test_modern_ip_and_route_spellings(self):
        self._hard(("shell ip addr del 10.0.1.5/24 dev eth0",
                    "shell ip a flush dev eth0", "shell ip l set eth0 down",
                    "shell route del default", "shell route flush",
                    "shell nmcli radio wifi off",
                    "shell nmcli device set eth0 managed no",
                    "shell ifconfig -a eth0 down"))

    def test_firewall_long_forms_and_restore(self):
        self._hard(("shell iptables --policy output drop",
                    "shell iptables-restore /tmp/rules.v4",
                    "shell ufw --force reset",
                    "shell nft delete table inet filter"))

    def test_relative_at_scheduler_forms(self):
        for cmd in ("shell at now + 1 minute /f c:\\x.exe",
                    "shell at -f /tmp/x now", "shell at midnight /f x.exe"):
            got = _classify(cmd)
            self.assertEqual((got.tier, got.action_key),
                             (safety.TIER_KNOCK, "persist"), cmd)

    def test_phase_five_promotion_is_not_shadowed_by_an_earlier_tier_two_hit(self):
        """The promoted refusal has to win over any other gated hit on the line."""
        for cmd in ("responder -I eth0 msfconsole", "crontab -e msfconsole"):
            self.assertEqual(
                safety.classify(cmd, target_kind="server",
                                is_uplink_iface=lambda n: False,
                                phase5_enabled=False).tier,
                safety.TIER_HARD, cmd)

    def test_interface_disconnect_is_one_rule_not_two(self):
        """Hard on the uplink, gated elsewhere — not tier-1 for both."""
        self.assertEqual(
            _classify("shell nmcli device disconnect eth0").tier, safety.TIER_HARD)
        got = _classify("shell nmcli device disconnect wlan1",
                        is_uplink_iface=lambda n: False)
        self.assertEqual((got.tier, got.action_key),
                         (safety.TIER_KNOCK, "iface_change"))

    def test_a_verb_in_a_readers_arguments_is_data(self):
        for cmd in ("grep reboot /var/log/syslog", "man reboot",
                    "ls /tmp/reboot", "cat /home/u/.bashrc",
                    "head -n 5 /var/log/auth.log"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_but_a_separator_ends_the_readers_protection(self):
        self._hard(("ls /tmp; iptables -F", "cat /etc/hosts && reboot"))

    def test_scan_limits_only_fire_in_command_position(self):
        for cmd in ("man nmap", "grep nmap /etc/services", "cat masscan.conf",
                    "ls nmap-results"):
            self.assertEqual(safety.enforce_scan_limits(cmd), cmd, cmd)

    def test_scan_limits_still_fire_behind_wrappers(self):
        for cmd in ("sudo nmap -sV 10.0.1.5", "shell sudo nmap -T5 10.0.1.5",
                    "timeout 600 nmap -sV 10.0.1.5",
                    "shell env nmap -sV 10.0.1.5"):
            self.assertIn("-T2 --max-rate 50", safety.enforce_scan_limits(cmd), cmd)


class TestFixRoundRegressions(unittest.TestCase):
    """Coverage the first fix round lost by narrowing patterns into checks.

    Each of these was tier 1 before that round, free after it, and is pinned
    here so the same trade cannot happen again: replacing a whole-line regex
    with a positional check is exactly where a guardrail quietly stops
    guarding.
    """

    def _hard(self, cmds, **kw):
        for cmd in cmds:
            self.assertEqual(_classify(cmd, **kw).tier, safety.TIER_HARD, cmd)

    def test_a_wipe_reached_through_an_introducer_is_still_a_wipe(self):
        self._hard(("xargs rm -rf /", "watch rm -rf /", "xargs -n 1 rm -rf /",
                    "su alice -c rm -rf /", "su - alice -c rm -rf /"))

    def test_wrapper_option_values_do_not_hide_the_program(self):
        self._hard(("timeout -s TERM 30 rm -rf /", "env -u FOO rm -rf /",
                    "stdbuf -o L rm -rf /",
                    "stdbuf -i 0 -o L dd if=/dev/zero of=/dev/sda",
                    "timeout -s TERM 7200 sleep 7200",
                    "env -u FOO kill 1234", "nice -n 19 sleep 7200",
                    "env FOO=bar reconfig"))

    def test_a_valueless_wrapper_flag_does_not_eat_the_program(self):
        """`env -i` takes no value; skipping a token after it hid the wipe."""
        self._hard(("env -i rm -rf /",))

    def test_a_signal_name_is_not_a_program(self):
        got = _classify("timeout -s KILL 600 whoami")
        self.assertEqual(got.tier, safety.TIER_FREE)

    def test_readers_that_execute_or_write_are_not_trusted(self):
        self._hard(("find /tmp -exec iptables -F +",))
        for cmd in ("sed -i s/x/y/ /home/u/.ssh/authorized_keys",
                    "sed -i s/x/y/ /etc/rc.local",
                    "awk -f /tmp/x.awk authorized_keys"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_KNOCK, cmd)

    def test_read_only_partition_tools_stay_free(self):
        """Refusing recon trains the operator to work around the guardrail."""
        for cmd in ("fdisk -l", "parted /dev/sda print", "badblocks -s /dev/sda"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_destructive_partition_subcommands_are_hard(self):
        self._hard(("fdisk /dev/sda", "parted /dev/sda mklabel gpt",
                    "badblocks -w /dev/sda"))

    def test_root_shorthands(self):
        self._hard(("rm -rf //", "rm -rf /.", "rm -rf ~/*"))

    def test_a_no_op_interface_set_is_not_refused(self):
        self.assertEqual(
            _classify("shell nmcli device set eth0 managed yes").tier,
            safety.TIER_FREE)

    def test_the_interface_verdict_does_not_pre_empt_the_phase_five_refusal(self):
        got = safety.classify("ifconfig wlan1 down msfconsole",
                              target_kind="beacon",
                              is_uplink_iface=lambda n: False,
                              phase5_enabled=False)
        self.assertEqual(got.tier, safety.TIER_HARD)

    def test_scan_limits_survive_a_separated_option_value(self):
        for cmd in ("timeout -s KILL 600 nmap -sV 10.0.1.5",
                    "nice -n 19 nmap -sV 10.0.1.5"):
            self.assertIn("-T2 --max-rate 50", safety.enforce_scan_limits(cmd), cmd)


class TestCommandPositionAndReaders(unittest.TestCase):
    """Round-3 boundary: a program is a program only in command position.

    The two previous rounds oscillated — checking index 0 only missed wipes
    behind an introducer, checking every token turned `man fdisk` into a hard
    refusal. Both directions are pinned here.
    """

    def _hard(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def _free(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_a_wipe_program_named_as_data_is_not_a_wipe(self):
        self._free(("man fdisk", "man mkfs", "man mkfs.ext4",
                    "ls -l /sbin/mkfs.ext4", "grep -i fdisk /var/log/syslog",
                    "grep mkfs /etc/fstab", "grep rm /dev/null",
                    "cp /bin/rm /dev/shm/x"))

    def test_but_in_command_position_it_still_is(self):
        self._hard(("xargs rm -rf /", "watch rm -rf /", "su alice -c rm -rf /",
                    "sh -c rm -rf /", "find /tmp -exec rm -rf / +"))

    def test_clustered_write_flags(self):
        """An exact-token test let `badblocks -wsv` through."""
        self._hard(("badblocks -wsv /dev/sda", "badblocks -vw /dev/sda"))
        self._free(("badblocks -s /dev/sda",))

    def test_partition_tools_read_only_vs_destructive(self):
        self._free(("fdisk -l", "fdisk -lu /dev/sda", "parted /dev/sda print"))
        self._hard(("fdisk /dev/sda", "parted /dev/sda mklabel gpt",
                    "parted /dev/sda"))

    def test_dd_is_destructive_only_when_writing_a_raw_device(self):
        self._hard(("dd if=/dev/zero of=/dev/mmcblk0", "dd of=/dev/sda bs=4m"))
        self._free(("dd if=/dev/urandom of=/tmp/x", "dd if=/dev/sda of=/tmp/img"))

    def test_any_non_reader_writing_a_block_device(self):
        """Catches the spellings no program-name rule knows."""
        self._hard(("xxd -r /tmp/hex /dev/sda", "tee /dev/sda"))
        self._free(("cat /dev/sda", "ls -l /dev/sda"))

    def test_conditional_readers_read_until_asked_to_act(self):
        self._free(("sed -n /reboot/p /var/log/syslog",
                    "awk /reboot/ /var/log/syslog", "find /tmp -name reboot"))
        self._hard(("find /tmp -exec iptables -F +",))
        for cmd in ("sed -i s/x/y/ /etc/rc.local",
                    "awk -f /tmp/x.awk authorized_keys"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_KNOCK, cmd)


class TestNeverRaises(unittest.TestCase):
    def test_hostile_input_returns_a_classification(self):
        for cmd in ("", "   ", "\n\n", "\x00", "sudo", "sudo -u", "shell",
                    "shell sudo", "a" * 100000, "\u202ereboot", "%s" * 50,
                    "((((", "[", "\\", "'", '"'):
            got = _classify(cmd)
            self.assertIsInstance(got, safety.Classification)
            self.assertIn(got.tier, (1, 2, 3))

    def test_non_string_input_is_refused_not_raised(self):
        for bad in (None, 5, b"reboot", ["reboot"]):
            self.assertEqual(_classify(bad).tier, safety.TIER_HARD)
            self.assertTrue(safety.has_shell_metachars(bad))

    def test_unrecognised_target_kind_is_treated_as_the_strictest(self):
        self.assertEqual(
            _classify("shell pkill -f bridge_tap.py", target_kind="???").tier,
            safety.TIER_HARD)


class TestScanLimits(unittest.TestCase):
    def test_injects_timing_and_rate_for_nmap(self):
        out = safety.enforce_scan_limits("nmap -sV 10.0.1.5")
        self.assertIn("-T2", out)
        self.assertIn("--max-rate 50", out)

    def test_strips_existing_aggressive_timing(self):
        out = safety.enforce_scan_limits("nmap -T5 --max-rate 10000 -sV 10.0.1.5")
        self.assertNotIn("-T5", out)
        self.assertNotIn("10000", out)
        self.assertIn("-T2", out)

    def test_masscan_rate_forced(self):
        self.assertIn("--rate 50", safety.enforce_scan_limits("masscan -p445 10.0.1.0/24"))

    def test_netdiscover_count_added_once(self):
        self.assertEqual(
            safety.enforce_scan_limits("netdiscover -c 1 -r 10.0.1.0/24").count("-c 1"), 1)

    def test_unrelated_command_untouched(self):
        self.assertEqual(safety.enforce_scan_limits("whoami"), "whoami")

    # ── Additional spellings ──

    def test_every_spelling_of_the_timing_flag_is_replaced(self):
        for flag in ("-T5", "-T 5", "-T insane", "-T4", "-Taggressive",
                     "--timing 5", "-T0"):
            out = safety.enforce_scan_limits("nmap %s -sV 10.0.1.5" % flag)
            self.assertEqual(out.count("-T2"), 1, flag)
            self.assertNotRegex(out, r"-T ?(?:[013-5]|insane|aggressive)\b", flag)

    def test_every_spelling_of_the_rate_flag_is_replaced(self):
        for flag in ("--max-rate 10000", "--max-rate=10000", "--min-rate 5000",
                     "--min-rate=5000"):
            out = safety.enforce_scan_limits("nmap %s 10.0.1.5" % flag)
            self.assertNotIn("10000", out, flag)
            self.assertNotIn("5000", out, flag)
            self.assertEqual(out.count("--max-rate 50"), 1, flag)

    def test_parallelism_flags_are_stripped(self):
        out = safety.enforce_scan_limits(
            "nmap --min-parallelism 100 --max-parallelism=256 --min-hostgroup 512 10.0.1.5")
        for gone in ("parallelism", "hostgroup", "256", "512"):
            self.assertNotIn(gone, out)

    def test_path_prefixed_and_sudo_binaries_are_limited(self):
        for cmd in ("/usr/bin/nmap -sV 10.0.1.5", "sudo nmap -sV 10.0.1.5",
                    "shell sudo /usr/local/bin/nmap -sV 10.0.1.5",
                    "NMAP -sV 10.0.1.5"):
            out = safety.enforce_scan_limits(cmd)
            self.assertIn("-T2 --max-rate 50", out, cmd)
            self.assertTrue(out.startswith(cmd.split("nmap")[0].split("NMAP")[0]), cmd)

    def test_masscan_existing_rate_is_replaced_in_any_spelling(self):
        for cmd in ("masscan --rate 100000 -p80 10.0.0.0/8",
                    "masscan --rate=100000 -p80 10.0.0.0/8",
                    "masscan --max-rate 100000 -p80 10.0.0.0/8",
                    "masscan -p80 --rate 100000 10.0.0.0/8",
                    "/usr/bin/masscan --rate 100000 -p80 10.0.0.0/8"):
            out = safety.enforce_scan_limits(cmd)
            self.assertNotIn("100000", out, cmd)
            self.assertEqual(out.count("--rate 50"), 1, cmd)

    def test_netdiscover_unbounded_gets_count_and_existing_count_is_capped(self):
        self.assertIn("-c 1", safety.enforce_scan_limits("netdiscover -r 10.0.1.0/24"))
        self.assertEqual(
            safety.enforce_scan_limits("netdiscover -c 500 -r 10.0.1.0/24").count("-c"), 1)
        self.assertIn("-c 1", safety.enforce_scan_limits("netdiscover -c 500 -r 10.0.1.0/24"))
        self.assertNotIn("-p", safety.enforce_scan_limits("netdiscover -r 10.0.1.0/24"))

    def test_is_idempotent(self):
        for cmd in ("nmap -sV 10.0.1.5", "masscan -p445 10.0.1.0/24",
                    "netdiscover -r 10.0.1.0/24", "shell sudo nmap -T5 10.0.1.5"):
            once = safety.enforce_scan_limits(cmd)
            self.assertEqual(safety.enforce_scan_limits(once), once, cmd)

    def test_word_containing_scanner_name_is_not_rewritten(self):
        for cmd in ("echo nmapper", "ls nmap-results", "cat masscan.conf"):
            self.assertEqual(safety.enforce_scan_limits(cmd), cmd)

    def test_does_not_raise_on_odd_input(self):
        for cmd in ("", "nmap", "nmap ", "masscan", "netdiscover", "-T5", None, 5):
            safety.enforce_scan_limits(cmd)


class TestScriptValidation(unittest.TestCase):
    def test_rejects_script_whose_any_line_is_blocked(self):
        code = "echo start\nrm -rf /opt/raccoon\necho done"
        self.assertIsNotNone(safety.validate_script(code, "bash"))

    def test_accepts_benign_script(self):
        self.assertIsNone(safety.validate_script("nmap -sn 10.0.1.0/24\nwhoami", "bash"))

    # ── Additional behaviour ──

    def test_message_names_the_first_offending_line_number(self):
        code = "# header\n\nwhoami\nreboot\niptables -F\n"
        msg = safety.validate_script(code, "bash")
        self.assertIn("line 4", msg)
        self.assertNotIn("line 5", msg)

    def test_comments_and_blank_lines_are_skipped(self):
        code = "#!/bin/bash\n# reboot\n   \n\t# iptables -F\nwhoami\n"
        self.assertIsNone(safety.validate_script(code, "bash"))

    def test_metacharacters_in_a_line_are_rejected(self):
        for code in ("whoami; id", "ls | grep x", "echo $(id)", "ls > out"):
            msg = safety.validate_script(code, "bash")
            self.assertIsNotNone(msg, code)
            self.assertIn("line 1", msg)

    def test_knock_tier_lines_are_rejected_in_stored_scripts(self):
        self.assertIsNotNone(safety.validate_script("responder -I eth0", "bash"))

    def test_crlf_line_endings_do_not_hide_a_line(self):
        msg = safety.validate_script("whoami\r\nreboot\r\n", "bash")
        self.assertIn("line 2", msg)

    def test_stored_script_gets_the_strictest_context(self):
        self.assertIsNotNone(safety.validate_script("pkill -f bridge_tap.py", "bash"))
        self.assertIsNotNone(safety.validate_script("ip link set wlan1 down", "bash"))
        self.assertIsNotNone(safety.validate_script("msfconsole -q", "bash"))

    def test_non_string_script_is_refused_not_raised(self):
        for bad in (None, 5, b"whoami"):
            self.assertIsNotNone(safety.validate_script(bad, "bash"))

    def test_empty_script_is_accepted(self):
        self.assertIsNone(safety.validate_script("", "bash"))


class TestClamp(unittest.TestCase):
    def test_clamps_to_plus_minus_two_tenths(self):
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.95), 0.70)
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.05), 0.30)
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.55), 0.55)

    def test_never_leaves_probability_range(self):
        self.assertLessEqual(safety.clamp_llm_adjustment(0.95, 1.5), 0.99)
        self.assertGreaterEqual(safety.clamp_llm_adjustment(0.05, -1.0), 0.01)

    def test_non_finite_proposals_fall_back_to_the_prior(self):
        for bad in (float("nan"), None, "high"):
            self.assertAlmostEqual(safety.clamp_llm_adjustment(0.4, bad), 0.4)

    def test_infinite_proposals_are_clamped_not_trusted(self):
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.5, float("inf")), 0.7)
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.5, float("-inf")), 0.3)


if __name__ == "__main__":
    unittest.main()

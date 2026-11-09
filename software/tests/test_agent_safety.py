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

    def test_the_tunnel_verb_is_hard_blocked(self):
        # `tunnel` reached the agent's vocabulary as a side effect rather
        # than as a decision: `test_agent_prompts` compares the beacon's
        # own dispatch table against `executor/beacon.py`'s copy for
        # equality, so adding the verb to the implant forced it into the
        # list the executor is prompted with. What it does is open or
        # close a SOCKS route into the target network, which an operator
        # drives from the panel. Until an agent doing that is a scoped
        # feature, it fails closed.
        for cmd in ("tunnel start", "tunnel stop", "tunnel", "TUNNEL start",
                    "sudo tunnel start"):
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

    def test_nft_rule_additions_that_drop_are_firewall_changes(self):
        self._hard(("shell nft add rule inet filter input drop",
                    "shell nft insert rule inet filter output ip daddr 10.0.0.1 drop",
                    "shell nft replace rule inet filter input handle 3 reject",
                    "shell nft create rule inet filter forward drop"))

    def test_nft_additions_that_do_not_drop_are_not_blocked(self):
        for cmd in ("shell nft add rule inet filter input accept",
                    "shell nft add table inet filter",
                    "shell nft list ruleset"):
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
                    "KILL", "  kill  ", "tunnel start", "  tunnel  stop  "))

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

    # ── Second spellings of listed effects ──

    def test_sqlmap_is_exploitation(self):
        self._assert_action(("sqlmap -u http://10.0.1.5/?id=1 --batch",
                             "python3 sqlmap.py -u http://10.0.1.5/?id=1"),
                            "exploit_known_poc")

    def test_remote_execution_tools_share_the_lateral_rule(self):
        # They share the action *class*, not the action key: see
        # TestLateralKeysAreNotShared for why the key had to be split out.
        self._assert_action((
            "impacket-psexec corp/a:b@10.0.1.5", "impacket-wmiexec corp/a:b@10.0.1.5",
            "impacket-smbexec corp/a:b@10.0.1.5", "impacket-atexec corp/a:b@10.0.1.5",
            "impacket-dcomexec corp/a:b@10.0.1.5", "psexec.py corp/a:b@10.0.1.5",
            "wmiexec.py corp/a:b@10.0.1.5", "smbexec.py corp/a:b@10.0.1.5",
            "atexec.py corp/a:b@10.0.1.5", "dcomexec.py corp/a:b@10.0.1.5",
            "evil-winrm -i 10.0.1.5 -u a -p b"), "remote_exec")
        self.assertEqual(self._c("evil-winrm -i 10.0.1.5").action_class, "lateral")

    def test_exe_suffixed_persistence_spellings(self):
        self._assert_action((
            "shell sc.exe create evil binpath= c:\\x.exe",
            "shell reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x",
            "shell net localgroup administrators backdoor /add"), "persist")

    def test_localgroup_listing_is_free(self):
        self.assertEqual(self._c("shell net localgroup administrators").tier,
                         safety.TIER_FREE)

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


class TestRoundFourFindings(unittest.TestCase):
    """The fourth re-review's findings. One was Critical.

    `_command_positions` is the right concept but its first implementation
    seeded only index 0, so a wipe after a shell separator was free — and the
    every-token scan it replaced had caught those. The block-device rule's
    premise ("any non-reader naming a device is writing to it") was simply
    false and refused mount, lsblk, smartctl and fsck at a tier with no
    operator override.
    """

    def _hard(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def _free(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_a_separator_introduces_a_command(self):
        self._hard(("ls ; rm -rf /", "ls;rm -rf /", "ls && rm -rf /",
                    "ls&&rm -rf /", "echo hi | rm -rf /", "echo a|rm -rf /",
                    "find . | xargs rm -rf /"))

    def test_a_nested_introducer_is_expanded(self):
        """One worklist; the two-loop split never recursed past -c."""
        for code in ("su alice -c xargs rm -rf /",
                     "nohup su alice -c xargs rm -rf /",
                     "find . -execdir xargs rm -rf / +"):
            self.assertIsNotNone(safety.validate_script(code, "bash"), code)

    def test_naming_a_device_is_not_writing_to_it(self):
        self._free(("mount /dev/sda1 /mnt", "lsblk /dev/sda",
                    "smartctl -a /dev/sda", "blkid /dev/sda",
                    "sha256sum /dev/sda", "cp /dev/sda /tmp/img",
                    "cryptsetup luksdump /dev/sda", "sgdisk -p /dev/sda",
                    "fsck /dev/sda1"))

    def test_but_a_writer_pointed_at_storage_is(self):
        self._hard(("tee /dev/sda", "xxd -r /tmp/hex /dev/sda",
                    "tee /dev/mapper/vg-root"))

    def test_storage_is_recognised_by_what_it_is_not(self):
        """An sd*/nvme* allowlist misses every LVM and by-id path."""
        self._hard(("dd if=/dev/zero of=/dev/mapper/vg-root",
                    "dd if=/dev/zero of=/dev/disk/by-id/ata-x",
                    "dd if=/dev/zero of=/dev/sr0",
                    "dd if=/dev/zero of=/dev/nbd0"))
        self._free(("dd if=/dev/zero of=/dev/null",
                    "dd if=/dev/urandom of=/tmp/x",
                    "dd if=/dev/sda of=/tmp/img"))

    def test_a_field_separator_is_not_a_script_flag(self):
        """Lowercasing turns awk's -F into -f; a prefix match then misfired."""
        self._free(("awk -F: /reboot/ /var/log/syslog",
                    "awk -F: /reboot/ /etc/passwd",
                    "sed -s /reboot/p /var/log/syslog"))
        for cmd in ("awk -f /tmp/x.awk authorized_keys",
                    "sed -i s/x/y/ /etc/rc.local",
                    "sed -i.bak s/x/y/ /etc/rc.local"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_KNOCK, cmd)

    def test_long_form_list_flags(self):
        self._free(("fdisk --list /dev/sda", "grep -- -la /dev/sda"))


class TestRoundFiveFindings(unittest.TestCase):
    """The fifth re-review's findings, and the end of the oscillation.

    Rounds 1–4 traded between a broad predicate that over-matched and a
    narrow program list that under-matched. Round 5 uses both: anything that
    is neither a reader nor a listed device inspector, pointing a write at
    storage, is destroying it. These tests pin both directions, because
    getting one right at the other's expense is what happened four times.
    """

    def _hard(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def _free(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_the_device_destruction_family_a_program_list_cannot_enumerate(self):
        self._hard(("cryptsetup luksformat /dev/sda", "cryptsetup erase /dev/sda",
                    "blkdiscard /dev/sda", "sgdisk -z /dev/sda",
                    "sgdisk --zap-all /dev/sda", "sfdisk /dev/sda",
                    "cfdisk /dev/sda", "mdadm --zero-superblock /dev/sda1",
                    "pvcreate /dev/sda", "lvremove /dev/vg/root",
                    "mke2fs /dev/sda1", "mkdosfs /dev/sda1", "mkswap /dev/sda2",
                    "nvme format /dev/nvme0", "debugfs -w /dev/sda",
                    "hdparm --security-erase p /dev/sda"))

    def test_read_only_device_inspection_stays_free(self):
        self._free(("mount /dev/sda1 /mnt", "umount /dev/sda1", "lsblk /dev/sda",
                    "blkid /dev/sda", "findmnt /dev/sda1", "fsck /dev/sda1",
                    "smartctl -a /dev/sda", "sha256sum /dev/sda",
                    "cryptsetup luksdump /dev/sda", "sgdisk -p /dev/sda",
                    "mdadm --detail /dev/md0", "hdparm -i /dev/sda",
                    "nvme list", "tune2fs -l /dev/sda1", "dumpe2fs /dev/sda1"))

    def test_direction_matters_for_copy_like_programs(self):
        """`cp image /dev/sdX` overwrites the disk; the reverse is imaging."""
        self._hard(("cp /tmp/img /dev/sda", "install /tmp/img /dev/sda"))
        self._free(("cp /dev/sda /tmp/img",))

    def test_tmpfs_and_pseudo_paths_are_not_storage(self):
        """/dev/shm is the framework's own staging area."""
        self._free(("tee /dev/shm/payload", "xxd -r hex.txt /dev/shm/payload",
                    "pv /dev/shm/data", "tee /dev/pts/0", "tee /dev/net/tun",
                    "tee /dev/null", "tee /dev/fd/1"))

    def test_arguments_end_at_the_next_command(self):
        """Giving each position the whole tail was wrong as well as slow."""
        self._free(("rm -rf /tmp ; ls /dev/sda",))
        self._hard(("rm -rf / ; ls /tmp", "ls /dev/sda ; tee /dev/sda"))

    def test_a_flag_is_never_a_program(self):
        self._free(("grep -- -la /dev/sda", "grep -c rm -rf / /var/log/auth.log",
                    "sort -c rm -rf /"))

    def test_but_a_shells_dash_c_still_introduces_one(self):
        self._hard(("su alice -c rm -rf /", "sh -c rm -rf /",
                    "su alice -c xargs rm -rf /"))

    def test_acting_flags_with_attached_values(self):
        for cmd in ("sed -f/tmp/x.sed /etc/rc.local",
                    "awk -f/tmp/x.awk authorized_keys",
                    "sed -nf/tmp/x.sed /etc/rc.local"):
            self.assertEqual(_classify(cmd).tier, safety.TIER_KNOCK, cmd)
        self._free(("awk -F: /reboot/ /var/log/syslog",))

    def test_an_interpreter_is_not_a_reader(self):
        self._hard(("perl script.pl /dev/sda",))

    def test_classification_is_linear_in_token_count(self):
        """20k chained introducers took 21 seconds before this round."""
        import time
        start = time.time()
        _classify("xargs " * 20000 + "rm -rf /")
        self.assertLess(time.time() - start, 2.0)

    def test_a_runtime_tier_one_rule_outranks_a_frozen_tier_two_hit(self):
        added = (safety.re.compile(r"\bfrobnicate\b"), "power_off")
        safety._RULES.append(added)
        try:
            got = _classify("frobnicate crontab -e")
        finally:
            safety._RULES.remove(added)
        self.assertEqual((got.tier, got.action_key), (safety.TIER_HARD, "power_off"))


class TestAdjudicationAndFinalCriticals(unittest.TestCase):
    """The two Criticals of the last re-review, and the adjudication.

    Five rounds enumerated read-only tools so that a broad write predicate
    would not refuse ordinary recon, and the list was never complete —
    sg_inq, dmsetup, mountpoint, e2label were all missing, each one an
    unoverridable refusal at tier 1. The adjudication: an unrecognised
    program writing storage earns a knock, not a refusal. An incomplete list
    then costs one approval click instead of blocking the agent.
    """

    def _hard(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_HARD, cmd)

    def _knock(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_KNOCK, cmd)

    def _free(self, cmds):
        for cmd in cmds:
            self.assertEqual(_classify(cmd).tier, safety.TIER_FREE, cmd)

    def test_double_dash_marks_options_not_a_command(self):
        """Treating `--` as a command bounded the real one's arguments."""
        self._hard(("rm -rf -- /", "shred -- /dev/sda", "tee -- /dev/sda",
                    "tee -a -- /dev/sda", "xxd -r hex.txt -- /dev/sda"))
        self._free(("grep -- -la /dev/sda",))

    def test_a_trailing_token_cannot_hide_a_destination(self):
        self._hard(("cp /tmp/img /dev/sda -v", "cp -a /tmp/img /dev/sda --verbose",
                    "cp /tmp/img /dev/sda >/dev/null",
                    "cp /tmp/img /dev/sda 2>/dev/null",
                    "mv /tmp/img /dev/sda >/dev/null",
                    "install /tmp/img /dev/sda >/dev/null",
                    "dcfldd if=/tmp/img of=/dev/sda"))
        self._free(("cp /dev/sda /tmp/img",))

    def test_an_exemption_requires_the_whole_invocation_to_be_read_only(self):
        """A harmless flag beside a destructive one used to exempt both."""
        self._hard(("hdparm -i --security-erase p /dev/sda",
                    "sgdisk -p -z /dev/sda", "sgdisk -p --zap-all /dev/sda",
                    "nvme id-ctrl /dev/nvme0 format"))
        self._free(("hdparm -i /dev/sda", "sgdisk -p /dev/sda",
                    "tune2fs -l /dev/sda1", "nvme list",
                    "cryptsetup luksdump /dev/sda", "mdadm --detail /dev/md0"))

    def test_recon_the_inspector_list_does_not_know_is_not_refused(self):
        self._free(("sg_inq /dev/sda", "mountpoint /dev/sda1",
                    "e2label /dev/sda1", "dmsetup info /dev/mapper/vg-root",
                    "bcache-super-show /dev/sda",
                    "fsfreeze --unfreeze /dev/sda1"))

    def test_an_unrecognised_program_writing_storage_asks(self):
        for cmd in ("someunknowntool /dev/sda", "pv /dev/sda",
                    "wipefs -n /dev/sda", "tune2fs -l /dev/sda1 -u random"):
            got = _classify(cmd)
            self.assertEqual(got.tier, safety.TIER_KNOCK, cmd)

    def test_recognised_destroyers_are_still_refused(self):
        self._hard(("cryptsetup luksformat /dev/sda", "blkdiscard /dev/sda",
                    "mke2fs /dev/sda1", "nvme format /dev/nvme0",
                    "mkfs.ext4 /dev/sda1",
                    "dd if=/dev/zero of=/dev/mapper/vg-root",
                    "rm -rf /", "tee /dev/sda"))

    def test_dry_runs_and_non_device_targets_are_not_refused(self):
        self._free(("blkdiscard -l", "mkswap /tmp/swapfile",
                    "mkfs.ext4 /tmp/img"))

    def test_the_dash_c_lookback_is_linear(self):
        """A prefix scan per `-c` token took 11 seconds at 8k of them."""
        import time
        start = time.time()
        _classify("gcc -c " * 20000)
        self.assertLess(time.time() - start, 2.0)


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

    def test_privilege_prefix_with_a_user_flag_still_finds_the_scanner(self):
        for cmd in ("sudo -u alice nmap -sV 10.0.1.5", "doas -u bob nmap -sV 10.0.1.5",
                    "sudo --user alice nmap -sV 10.0.1.5",
                    "sudo -g wheel -u alice nmap -sV 10.0.1.5",
                    "runas -U alice nmap -sV 10.0.1.5"):
            out = safety.enforce_scan_limits(cmd)
            self.assertIn("nmap -T2 --max-rate 50 -sV 10.0.1.5", out, cmd)
            self.assertEqual(safety.enforce_scan_limits(out), out, cmd)

    def test_plain_privilege_and_bare_scanner_are_still_limited(self):
        self.assertEqual(safety.enforce_scan_limits("sudo nmap -sV 10.0.1.5"),
                         "sudo nmap -T2 --max-rate 50 -sV 10.0.1.5")
        self.assertEqual(safety.enforce_scan_limits("nmap -sV 10.0.1.5"),
                         "nmap -T2 --max-rate 50 -sV 10.0.1.5")

    def test_privilege_user_value_is_not_mistaken_for_the_scanner_position(self):
        for cmd in ("sudo -u alice whoami", "sudo -u nmap whoami"):
            self.assertEqual(safety.enforce_scan_limits(cmd), cmd)

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

    # ── Language handling ──

    _BENIGN_PYTHON = (
        "import socket\n"
        "# probe the gateway\n"
        "def probe(host, port=445):\n"
        "    s = socket.socket()\n"
        "    s.settimeout(2)\n"
        "    ok = s.connect_ex((host, port)) == 0\n"
        "    return {'host': host, 'open': ok}\n"
        "print(probe('10.0.1.5'))\n")

    def test_benign_python_script_is_accepted(self):
        self.assertIsNone(safety.validate_script(self._BENIGN_PYTHON, "python"))

    def test_python_punctuation_is_still_shell_metacharacters_to_bash(self):
        msg = safety.validate_script(self._BENIGN_PYTHON, "bash")
        self.assertIn("shell metacharacters", msg)

    def test_python_shell_escape_names_line_and_construct(self):
        code = "import os\nx = 1\nsubprocess.run(['id'])\nos.system('id')\n"
        msg = safety.validate_script(code, "python")
        self.assertIn("line 3", msg)
        self.assertIn("subprocess", msg)
        self.assertNotIn("line 4", msg)

    def test_every_python_shell_escape_is_refused(self):
        for line, construct in (
                ("import subprocess", "subprocess"), ("os.system('id')", "os.system"),
                ("os.popen('id')", "os.popen"), ("os.execv('/bin/sh', [])", "os.exec"),
                ("os . system('id')", "os.system"),
                ("eval(payload)", "eval("), ("exec (payload)", "exec("),
                ("m = __import__('os')", "__import__"),
                ("pty.spawn('/bin/sh')", "pty.spawn"),
                ("commands.getoutput('id')", "commands.getoutput")):
            msg = safety.validate_script("x = 1\n" + line, "python")
            self.assertIsNotNone(msg, line)
            self.assertIn("line 2", msg, line)
            self.assertIn(construct, msg, line)

    def test_python_lookalikes_are_not_shell_escapes(self):
        for line in ("import ast", "v = ast.literal_eval('[1, 2]')",
                     "path = os.path.join('a', 'b')", "pos.systematic = 1"):
            self.assertIsNone(safety.validate_script(line, "python"), line)

    def test_python_is_not_classified_as_shell_commands(self):
        self.assertIsNone(safety.validate_script("reboot = 3", "python"))

    def test_shell_dialects_and_unknown_languages_take_the_strict_path(self):
        for language in ("bash", "sh", "zsh", "dash", "ruby", "", None):
            self.assertIsNotNone(safety.validate_script("whoami; id", language), language)
            self.assertIsNotNone(safety.validate_script("reboot", language), language)
            self.assertIsNone(safety.validate_script("whoami", language), language)


class TestPythonScriptsCannotReachTierOneEffects(unittest.TestCase):
    """Skipping command classification for python must not restore the bypass.

    The shell path hard-blocks filesystem destruction, raw block-device access
    and killing a process. None of those three needs a shell, so a language
    branch that only screens for shell escapes would let the same effects
    through by rewriting the destroyer in python — which is the bypass
    `validate_script` exists to close, in a narrower spelling.
    """

    def test_filesystem_destruction_is_refused_without_a_shell(self):
        for line, construct in (
                ("shutil.rmtree('/')", "shutil.rmtree"),
                ("os.remove('/etc/shadow')", "os.remove"),
                ("os.unlink('/etc/shadow')", "os.unlink"),
                ("os.rmdir('/var')", "os.rmdir"),
                ("os.removedirs('/var/log')", "os.removedirs"),
                ("os.truncate('/etc/passwd', 0)", "os.truncate"),
                ("Path('/etc/shadow').unlink()", ".unlink(")):
            msg = safety.validate_script("x = 1\n" + line, "python")
            self.assertIsNotNone(msg, line)
            self.assertIn("line 2", msg, line)
            self.assertIn(construct, msg, line)

    def test_raw_block_devices_are_refused_in_either_direction(self):
        for device in ("/dev/sda", "/dev/nvme0n1", "/dev/hdb", "/dev/mmcblk0",
                       "/dev/disk0", "/dev/rdisk0"):
            for line in ("open('%s', 'wb').write(b'x')" % device,
                         "data = open('%s', 'rb').read()" % device):
                msg = safety.validate_script(line, "python")
                self.assertIsNotNone(msg, line)
                self.assertIn("destroys or kills", msg, line)

    def test_killing_a_process_is_refused(self):
        for line in ("os.kill(pid, 9)", "os.killpg(group, 9)"):
            self.assertIsNotNone(safety.validate_script(line, "python"), line)

    def test_arbitrary_code_reach_counts_as_a_shell_escape(self):
        for line, construct in (("import ctypes", "ctypes"),
                                ("ctypes.CDLL('libc.so.6').system(b'id')", "ctypes"),
                                ("import importlib", "importlib"),
                                ("importlib.import_module('os')", "importlib"),
                                ("os.spawnv(os.P_WAIT, '/bin/sh', [])", "os.spawn")):
            msg = safety.validate_script(line, "python")
            self.assertIsNotNone(msg, line)
            self.assertIn(construct, msg, line)

    def test_benign_stdlib_use_still_passes(self):
        for line in ("path = os.path.join('a', 'b')",
                     "v = ast.literal_eval('[1, 2]')",
                     "seed = open('/dev/urandom', 'rb').read(4)",
                     "sink = open('/dev/null', 'w')",
                     "s = socket.socket()",
                     "cwd = os.getcwd()",
                     "entries = os.listdir('/etc')",
                     "shutil.copy('a', 'b')",
                     "unlinked = 1",
                     "pos.systematic = 1"):
            self.assertIsNone(safety.validate_script(line, "python"), line)

    def test_a_destructive_python_line_is_reported_with_its_number(self):
        code = "import shutil\nx = 1\nshutil.rmtree('/')\nos.remove('/etc/x')\n"
        msg = safety.validate_script(code, "python")
        self.assertIn("line 3", msg)
        self.assertNotIn("line 4", msg)


class TestLateralKeysAreNotShared(unittest.TestCase):
    """The gate keys approvals and detection history on `action_key`.

    Two different actions behind one key means an approval granted for the
    first silently authorises the second, so a shared key is an
    authorisation-widening bug rather than a labelling one.
    """

    def test_remote_execution_has_its_own_key(self):
        for command in ("shell psexec.py corp/admin@10.0.1.5",
                        "shell wmiexec.py corp/admin@10.0.1.5",
                        "shell smbexec.py corp/admin@10.0.1.5",
                        "shell atexec.py corp/admin@10.0.1.5",
                        "shell dcomexec.py corp/admin@10.0.1.5",
                        "shell impacket-psexec corp/admin@10.0.1.5",
                        "shell evil-winrm -i 10.0.1.5 -u admin"):
            verdict = _classify(command)
            self.assertEqual(verdict.tier, safety.TIER_KNOCK, command)
            self.assertEqual(verdict.action_key, "remote_exec", command)
            self.assertEqual(verdict.action_class, "lateral", command)

    def test_coercion_keeps_the_relay_key(self):
        for command in ("shell ntlmrelayx.py -tf targets.txt",
                        "shell petitpotam.py 10.0.1.5 10.0.1.6",
                        "shell dfscoerce.py -u a 10.0.1.5"):
            verdict = _classify(command)
            self.assertEqual(verdict.action_key, "ntlm_relay", command)

    def test_the_two_reasons_describe_different_actions(self):
        relay = _classify("shell ntlmrelayx.py -tf targets.txt").reason
        remote = _classify("shell psexec.py corp/admin@10.0.1.5").reason
        self.assertNotEqual(relay, remote)
        self.assertIn("relay", relay)
        self.assertIn("another host", remote)

    def test_remote_service_creation_is_persistence_with_or_without_a_host(self):
        for command in (r"shell sc \\dc01 create svc binPath= C:\evil.exe",
                        "shell sc create svc binPath= evil.exe",
                        "shell sc.exe create svc binPath= evil.exe"):
            verdict = _classify(command)
            self.assertEqual(verdict.tier, safety.TIER_KNOCK, command)
            self.assertEqual(verdict.action_key, "persist", command)

    def test_service_queries_stay_free(self):
        for command in ("shell sc query svc", "shell sc qc svc",
                        r"shell sc \\dc01 query svc"):
            self.assertEqual(_classify(command).tier, safety.TIER_FREE, command)


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



class TestAnAllPortsScanIsNarrowed(unittest.TestCase):
    """At a forced 50 packets a second, -p- is not a scan but a timeout.

    Observed twice live. 65535 ports at --max-rate 50 is about 22 minutes of
    port scanning alone, against nmap's 900-second limit, so the run comes
    back as partial output with success false -- and with -sV requested, the
    version detection never starts at all. That is what blocked a campaign
    from ever confirming a service version.

    Telling the model was tried first and did not work: the scan section
    states the duration and the limit, and the model asked for
    `nmap -sS -sV -p- 192.168.64.5` anyway. A limit that only exists in the
    prompt is a suggestion.

    --top-ports is nmap's own frequency ordering rather than a list chosen
    here, and it only applies where the rate limit does: the router calls
    this function only when limit_scan_rate is set, so the yolo profile
    lifts the narrowing with the rest.
    """

    def _narrowed(self, command):
        return safety.enforce_scan_limits(command)

    def test_dash_p_dash_is_replaced(self):
        out = self._narrowed("nmap -sV -p- 10.0.1.5")
        self.assertNotIn("-p-", out)
        self.assertIn("--top-ports", out)

    def test_a_written_out_full_range_is_replaced(self):
        for spelling in ("-p 1-65535", "-p1-65535", "-p 0-65535",
                         "--ports 1-65535"):
            out = self._narrowed("nmap %s 10.0.1.5" % spelling)
            self.assertIn("--top-ports", out, spelling)
            self.assertNotIn("65535", out, spelling)

    def test_a_named_port_list_is_left_alone(self):
        out = self._narrowed("nmap -sV -p 22,80,443 10.0.1.5")
        self.assertIn("-p 22,80,443", out)
        self.assertNotIn("--top-ports", out)

    def test_a_modest_range_is_left_alone(self):
        out = self._narrowed("nmap -p 1-1024 10.0.1.5")
        self.assertIn("-p 1-1024", out)
        self.assertNotIn("--top-ports", out)

    def test_the_rewrite_is_idempotent(self):
        once = self._narrowed("nmap -sV -p- 10.0.1.5")
        self.assertEqual(self._narrowed(once), once)

    def test_the_target_survives_the_rewrite(self):
        self.assertIn("10.0.1.5", self._narrowed("nmap -p- 10.0.1.5"))

    def test_the_rate_limit_is_still_applied(self):
        self.assertIn("-T2 --max-rate 50", self._narrowed("nmap -p- 10.0.1.5"))

    def test_a_non_scanner_mention_is_untouched(self):
        for cmd in ("man nmap", "grep -- -p- /etc/nmap.conf"):
            self.assertEqual(self._narrowed(cmd), cmd, cmd)

    def test_a_common_service_port_is_inside_the_kept_set(self):
        # The point of using nmap's own ordering: the narrowing must not
        # hide the ports an enumeration phase exists to find. Read from
        # nmap-services where it is available, so this is a claim about
        # nmap's list and not about a number written here.
        import pathlib
        import re
        for candidate in ("/opt/homebrew/share/nmap/nmap-services",
                          "/usr/local/share/nmap/nmap-services",
                          "/usr/share/nmap/nmap-services"):
            path = pathlib.Path(candidate)
            if path.exists():
                break
        else:
            self.skipTest("nmap-services not installed")
        rows = []
        for line in path.read_text().splitlines():
            m = re.match(r"^(\S+)\s+(\d+)/tcp\s+([\d.]+)", line)
            if m:
                rows.append((float(m.group(3)), int(m.group(2))))
        rows.sort(key=lambda r: -r[0])
        kept = {port for _, port in rows[:safety.SCAN_TOP_PORTS]}
        for port in (21, 22, 80, 443, 445, 3389):
            self.assertIn(port, kept, port)


class TestTheProgramIsFoundWhereverItIs(unittest.TestCase):
    """is_scan, takes_network_targets and enforce_scan_limits must agree
    with classify about where the program is.

    classify normalises first -- quotes stripped, backslashes folded, case
    lowered -- but _program_position split the raw string, so a quoted
    program name or a privilege wrapper whose option value it did not know
    hid the program from all three. Both consequences are fail-open:

      "nmap" -sV -p- 10.0.1.5              no rate limit, no port cap
      pkexec -u alice nxc smb /tmp/hosts   require_target off, scope allows

    The second is the one that matters. Paths are deliberately no longer
    refused outright, so `require_target` is the only thing standing
    between a targets-from-a-file command and execution; with the program
    hidden it is False, the scope finds nothing to check, and the command
    runs with no verdict at all.

    `sudo`, `doas` and `runas` were fixed in an earlier round and have
    tests. `pkexec` sits in the same privilege tuple in _program_position
    and was left out of the value-flag table, so the earlier finding was
    closed on three spellings of four. These tests assert the property --
    the answer does not depend on how the program was spelled -- rather
    than the four spellings that exist today.
    """

    SCAN = "nmap -sV -p- 10.0.1.5"
    FILE_TARGETS = "nxc smb /tmp/hosts"

    def _wrapped(self, command):
        return ('%s' % command,
                '"%s"' % command.split()[0] + " " + command.split(None, 1)[1],
                "sudo " + command,
                "sudo -u alice " + command,
                "doas -u alice " + command,
                "pkexec -u alice " + command,
                "pkexec --user alice " + command,
                "shell " + command,
                "timeout -s KILL 600 " + command,
                "env -u LD_PRELOAD " + command)

    def test_a_scan_is_recognised_however_it_is_spelled(self):
        for form in self._wrapped(self.SCAN):
            self.assertTrue(safety.is_scan(form), form)

    def test_the_rate_limit_is_applied_however_it_is_spelled(self):
        for form in self._wrapped(self.SCAN):
            limited = safety.enforce_scan_limits(form)
            self.assertIn("--max-rate 50", limited, form)
            self.assertIn("--top-ports", limited, form)
            self.assertNotIn("-p-", limited, form)

    def test_a_network_tool_needs_a_target_however_it_is_spelled(self):
        for form in self._wrapped(self.FILE_TARGETS):
            self.assertTrue(safety.takes_network_targets(form), form)

    def test_every_privilege_wrapper_in_the_table_knows_its_value_flags(self):
        # The gap was a wrapper named in _program_position's privilege
        # tuple with no entry in the value-flag table, so its -u swallowed
        # the program. Asserted as a property of the two tables rather than
        # as a list of spellings.
        for name in ("sudo", "doas", "runas", "pkexec"):
            self.assertIn(name, safety._WRAPPER_VALUE_FLAGS, name)
            self.assertIn("-u", safety._WRAPPER_VALUE_FLAGS[name], name)



class TestTheTwoTargetPredicates(unittest.TestCase):
    """The two halves the router composes; the composition is tested there.

    Deliberately not one predicate with a negation: three answers exist,
    and the third is "nobody listed this program". Collapsing it into
    either of the other two is what made `wget -i /tmp/urls.txt` pass with
    no scope verdict, and then what made `shutdown -h now` be answered with
    "name a target".
    """

    LOCAL = ("ip addr show", "netstat -rn", "cat /etc/resolv.conf",
             "hostname -f", "uname -srm", "whoami", "pwd", "ls /opt",
             "which cve-search", "searchsploit dnsmasq", "df -h /",
             "scutil --get ComputerName", "lsof -i -n -P", "ps -ef")
    NETWORK = ("nmap -sV 10.0.1.5", "nxc smb 10.0.1.5", "smbclient -L x",
               "ldapsearch -x", "hydra -l a -P b ssh://x", "sqlmap -u x")
    UNKNOWN = ("wget -i /tmp/u", "curl -K /tmp/u", "custom-sweeper --targets f",
               "ssh admin@h", "rsync -a a b")

    def test_a_host_local_program_is_recognised(self):
        for command in self.LOCAL:
            self.assertTrue(safety.is_host_local(command), command)
            self.assertFalse(safety.takes_network_targets(command), command)

    def test_a_known_network_tool_is_recognised(self):
        for command in self.NETWORK:
            self.assertTrue(safety.takes_network_targets(command), command)
            self.assertFalse(safety.is_host_local(command), command)

    def test_an_unlisted_program_is_neither(self):
        for command in self.UNKNOWN:
            self.assertFalse(safety.is_host_local(command), command)
            self.assertFalse(safety.takes_network_targets(command), command)

    def test_nothing_readable_is_not_host_local(self):
        for command in ("", "   ", None, 42, "|"):
            self.assertFalse(safety.is_host_local(command), repr(command))

    def test_the_wrappers_do_not_change_either_answer(self):
        for prefix in ("", "sudo ", "sudo -u alice ", "pkexec -u alice ",
                       "shell ", "timeout -s KILL 600 ", "env -u LD_PRELOAD "):
            self.assertTrue(safety.is_host_local(prefix + "ip addr show"),
                            prefix)
            self.assertTrue(
                safety.takes_network_targets(prefix + "nmap 10.0.1.5"), prefix)


class TestTheHostLocalListHoldsNoWrapper(unittest.TestCase):
    """A wrapper in _HOST_LOCAL_TOOLS hides the program it wraps.

    _program_position checks membership before it skips wrappers, so a
    wrapper listed as host-local stops the scan at itself and whatever
    follows is never read. `shell wget -i /tmp/u` and
    `env -u LD_PRELOAD nxc smb /tmp/hosts` both came back host-local that
    way while the inversion was being written -- fail-open, and silent.
    """

    def test_the_two_sets_are_disjoint(self):
        wrappers = set(safety._WRAPPERS) | {"shell", "sudo", "doas",
                                            "runas", "pkexec"}
        self.assertEqual(sorted(wrappers & set(safety._HOST_LOCAL_TOOLS)), [])



class TestXxdWritesWithOrWithoutTheRevertFlag(unittest.TestCase):
    """xxd's second operand is its output file in both directions.

    `-r` chooses the encoding, not the direction of the write, so a reader
    exemption keyed on `-r` let the other spelling destroy a device at
    tier 3:

        xxd -r /tmp/hex /dev/sda   tier 1  disk_wipe
        xxd    /tmp/hex /dev/sda   tier 3  -- also writes /dev/sda

    xxd is in _KNOWN_DESTROYERS and never reached it, because _is_reader
    returned True first and that shortcut bypasses the write predicate.
    The suite pinned only the `-r` spelling, which is the "second way to
    ask" pattern it otherwise catches well.

    The rule is the operand count, not the flag: one bare operand reads,
    two write the second one.
    """

    def _tier(self, command):
        return safety.classify(command, "dropbox", lambda n: False,
                               True).tier

    def test_a_write_to_a_device_is_tier_one_either_way(self):
        for command in ("xxd -r /tmp/hex /dev/sda",
                        "xxd /tmp/hex /dev/sda",
                        "xxd -p /tmp/hex /dev/nvme0n1",
                        "sudo xxd /tmp/hex /dev/disk0"):
            self.assertEqual(self._tier(command), safety.TIER_HARD, command)

    def test_reading_one_file_is_still_free(self):
        for command in ("xxd /etc/passwd", "xxd -r /tmp/hex",
                        "xxd -l 64 /dev/sda", "xxd -p /etc/hosts"):
            self.assertEqual(self._tier(command), safety.TIER_FREE, command)

    def test_a_write_to_an_ordinary_path_is_not_a_device_wipe(self):
        # Two operands where the second is not a device: no longer a
        # reader, but nothing destroys a disk either.
        self.assertEqual(self._tier("xxd /tmp/in /tmp/out"),
                         safety.TIER_FREE)



class TestASleepWithAUnitIsReadNotGuessed(unittest.TestCase):
    """`sleep 30s` was a tier-1 refusal with an untrue reason.

    float("30s") raises, the except arm returned sleep_too_long, and its
    reason reads "a sleep this long takes the beacon out of reach for
    hours" -- which is false for thirty seconds, and the model has no way
    to read it and comply. Fail-closed, so harmless, but a refusal nobody
    can act on is a refusal that will be retried.
    """

    def _c(self, command):
        return safety.classify(command, "dropbox", lambda n: False, True)

    def test_a_short_sleep_with_a_unit_is_free(self):
        for command in ("sleep 30s", "sleep 1m", "sleep 0.5s", "sleep 90s",
                        "sleep 2m"):
            self.assertEqual(self._c(command).tier, safety.TIER_FREE, command)

    def test_a_long_sleep_with_a_unit_is_still_refused(self):
        for command in ("sleep 5h", "sleep 400m", "sleep 2d", "sleep 99999s"):
            c = self._c(command)
            self.assertEqual(c.tier, safety.TIER_HARD, command)
            self.assertEqual(c.action_key, "sleep_too_long", command)

    def test_something_unparseable_says_what_it_wants(self):
        # Still refused -- fail-closed -- but with a reason that can be
        # acted on instead of one that is untrue.
        c = self._c("sleep soon")
        self.assertEqual(c.tier, safety.TIER_HARD)
        self.assertIn("seconds", (c.reason or "").lower())

    def test_the_plain_forms_are_unchanged(self):
        self.assertEqual(self._c("sleep 30").tier, safety.TIER_FREE)
        self.assertEqual(self._c("sleep 99999").action_key, "sleep_too_long")


class TestARepeatedFlagIsReadAtItsOwnPosition(unittest.TestCase):
    """`nmap -p 80 -p - 10.0.1.5` kept the all-ports request.

    next_token looked the flag's value up with list.index, which finds the
    *first* token of that value rather than the one being examined. With
    `-p` given twice, the second one's value was read from the first, so
    `-p -` survived the narrowing and produced exactly the 22-minute
    timeout the cap exists to prevent.
    """

    def test_the_second_occurrence_is_the_one_capped(self):
        out = safety.enforce_scan_limits("nmap -p 80 -p - 10.0.1.5")
        self.assertIn("--top-ports", out)
        self.assertNotIn("-p -", out)

    def test_a_repeated_narrow_flag_is_left_alone(self):
        out = safety.enforce_scan_limits("nmap -p 80 -p 443 10.0.1.5")
        self.assertNotIn("--top-ports", out)
        self.assertIn("-p 80", out)
        self.assertIn("-p 443", out)

    def test_the_cap_appears_once_however_many_times_it_was_asked(self):
        out = safety.enforce_scan_limits("nmap -p - -p - 10.0.1.5")
        self.assertEqual(out.count("--top-ports"), 1)


class TestXargsFlagsDoNotHideTheProgram(unittest.TestCase):
    """A wrapper's flag table is load-bearing in both directions.

    Found by the drift test between safety's and scope's tables. xargs had
    `--replace` listed as taking a separate value -- it does not, GNU
    xargs takes it attached -- so the token after it was skipped and the
    program went with it. And `-I`, which genuinely does take one, was in
    neither table, so its replacement string landed in command position.
    Both are Critical 1's shape: the program hidden, the rate limit gone,
    and `require_target` relying on a program it cannot see.

        xargs --replace nmap -sV -p- 10.0.1.5   scan=False, unlimited
        xargs -I {} nmap -sV -p- 10.0.1.5       scan=False, unlimited
    """

    SPELLINGS = (
        "xargs nmap -sV -p- 10.0.1.5",
        "xargs -n 1 nmap -sV -p- 10.0.1.5",
        "xargs -I {} nmap -sV -p- 10.0.1.5",
        "xargs --replace nmap -sV -p- 10.0.1.5",
        "xargs -i nmap -sV -p- 10.0.1.5",
        "xargs -L 1 nmap -sV -p- 10.0.1.5",
        "xargs -a /tmp/list nmap -sV -p- 10.0.1.5",
        "xargs -d , -P 4 nmap -sV -p- 10.0.1.5",
    )

    def test_the_scanner_is_found_behind_every_spelling(self):
        for command in self.SPELLINGS:
            self.assertTrue(safety.is_scan(command), command)

    def test_the_rate_limit_and_the_cap_survive_every_spelling(self):
        for command in self.SPELLINGS:
            limited = safety.enforce_scan_limits(command)
            self.assertIn("--max-rate 50", limited, command)
            self.assertIn("--top-ports", limited, command)
            self.assertNotIn("-p-", limited, command)

    def test_an_attached_replacement_string_is_not_a_program(self):
        # `-I{}` carries its value, so nothing after it may be skipped.
        self.assertTrue(safety.is_scan("xargs -I{} nmap -p- 10.0.1.5"))

if __name__ == "__main__":
    unittest.main()

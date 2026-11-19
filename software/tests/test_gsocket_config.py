#!/usr/bin/env python3
"""
Unit tests for the gsocket carrier's configuration: the two blocks that
look alike and mean opposite things.

What these tests are careful about.

**Both sides, kept apart.** `c2.gsocket_carrier` is this host as a
*server* -- the carrier processes the team server runs beside its own
beacon socket. `c2.fallback.gsocket` is this host as a *client* -- the
leg an implant running here will try. The names do not say which is
which, so one test asserts that a `local_port` written into the server
block is refused by name: that value belongs to the implant's forward and
has no reader on the server side, and a key that is silently dropped
looks exactly like one that was applied.

**A disabled entry is held to the same standard as an enabled one.** Two
tests exist only for that, because the alternative is a typo that waits
for the day somebody switches the carrier on, which is the worst possible
moment for it to appear. What `enabled` does change is *presence*: the
implant's `secret_file` is minted per build by the generator, so a
disabled leg may not have one yet -- the same rule `c2.encryption_key`
already follows ("required while fallback.enabled is true").

**Both ends carry a digest, and that is deliberate symmetry rather than
duplication.** The server verifies the `gs-netcat` a carrier execs and
the implant verifies its own, with a copy of the same check rather than
an import of it, because `beacon.py` may use only the standard library.
So `sha256` is a key on both sides here: a copy with nowhere to read the
expected digest from would fall back to "the file exists and is
executable" while reporting the same reasons as the real check.

**Every refusal is asked to name the offending value.** A config error
here surfaces at runtime as a carrier that joins the relay network and
never finds its peer, which reads as a relay problem rather than as a
wrong number, so the message has to carry what it read and not only
which key it read. Asserting the *setting's name* alone would not hold
that: the name is in the label and survives any change that drops the
value. So every refusal family asserts the value as the message prints
it -- `repr`, since the module interpolates `%r` -- alongside the name.
Where a value is empty, `''` and `'   '` are different mistakes and the
second is invisible in the file it came from, so the refusal prints that
too.

**The defaults are checked as values, not as behaviour.** `beacon.py` is
served to a target as source text and may import only the standard
library, so Task 6 carries a *copy* of these five numbers. A test that
only asked "does a missing key get filled" would pass against a module
whose numbers had drifted from the copy, so `LEG_DEFAULTS` is asserted
key by key.
"""

import dataclasses
import unittest

from software.c2.gsocket.config import (
    LEG_DEFAULTS,
    CarrierSpec,
    load_carriers,
    validate_leg,
)


def carrier_entry(**overrides):
    """A carrier entry that loads, for a test to spoil one field of."""
    entry = {
        "name": "gs-pi-01",
        "identity": "pi-01",
        "enabled": True,
        "beacon_host": "127.0.0.1",
        "beacon_port": 8443,
        "binary_path": "/usr/bin/gs-netcat",
    }
    entry.update(overrides)
    return entry


def config_with(*entries):
    return {"c2": {"gsocket_carrier": list(entries)}}


def leg_block(**overrides):
    """A leg block that validates, for a test to spoil one field of."""
    block = {
        "enabled": True,
        "secret_file": "/var/lib/raccoon/gsocket.key",
        "binary_path": "/opt/raccoon/bin/gs-netcat",
    }
    block.update(overrides)
    return block


class TestCarrierBlock(unittest.TestCase):
    """`c2.gsocket_carrier`: this host as a server."""

    def test_no_block_yields_no_carriers(self):
        # Every deployment that predates this feature has no such block,
        # and all of them have to keep starting -- the same answer
        # `load_listeners` gives.
        for config in (None, {}, {"c2": None}, {"c2": {}},
                       {"c2": {"gsocket_carrier": None}},
                       {"c2": {"gsocket_carrier": []}},
                       "not a config at all"):
            with self.subTest(config=config):
                self.assertEqual(load_carriers(config), [])

    def test_a_configured_carrier_comes_back_validated(self):
        specs = load_carriers(config_with(carrier_entry(
            sha256="A" * 64)))
        self.assertEqual(len(specs), 1)
        spec = specs[0]
        self.assertEqual(spec.name, "gs-pi-01")
        self.assertEqual(spec.identity, "pi-01")
        self.assertTrue(spec.enabled)
        self.assertEqual(spec.beacon_host, "127.0.0.1")
        self.assertEqual(spec.beacon_port, 8443)
        self.assertEqual(spec.binary_path, "/usr/bin/gs-netcat")
        # Lower-cased, because what it is compared against is
        # `hashlib.sha256(...).hexdigest()`, which is lower-case.
        self.assertEqual(spec.sha256, "a" * 64)

    def test_a_carrier_spec_has_no_local_port(self):
        # Deliberate: the server side runs `gs-netcat -l -d <beacon_host>
        # -p <beacon_port>` and opens no forward of its own, so a
        # `local_port` here would be a configurable value with no reader.
        # The implant's forward port is `c2.fallback.gsocket.local_port`.
        fields = [field.name for field in dataclasses.fields(CarrierSpec)]
        self.assertEqual(
            fields,
            ["name", "identity", "enabled", "beacon_host", "beacon_port",
             "binary_path", "sha256"])

    def test_a_disabled_carrier_is_validated_as_strictly_as_an_enabled_one(self):
        # A typo that waits until the day somebody switches the carrier on
        # has chosen the worst possible moment to appear.
        for spoiled in (
                {"beacon_port": 0},
                {"beacon_port": "8443"},
                {"identity": ""},
                {"beacon_host": "0.0.0.0"},
                {"binary_path": "gs-netcat"},
                {"sha256": "nothex"},
        ):
            with self.subTest(spoiled=spoiled):
                entry = carrier_entry(enabled=False, **spoiled)
                with self.assertRaises(ValueError):
                    load_carriers(config_with(entry))
        # And a disabled entry that is otherwise sound loads, disabled:
        # strictness is about the values, not about refusing the switch.
        specs = load_carriers(config_with(carrier_entry(enabled=False)))
        self.assertEqual([spec.enabled for spec in specs], [False])

    def test_two_carriers_with_one_identity_are_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_carriers(config_with(
                carrier_entry(name="gs-a", identity="pi-01"),
                carrier_entry(name="gs-b", identity="pi-01")))
        message = str(caught.exception)
        self.assertIn("pi-01", message)
        self.assertIn("gs-a", message)
        self.assertIn("gs-b", message)

    def test_two_carriers_with_one_name_are_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_carriers(config_with(
                carrier_entry(name="gs-a", identity="pi-01"),
                carrier_entry(name="gs-a", identity="pi-02")))
        self.assertIn("gs-a", str(caught.exception))

    def test_a_carrier_without_an_identity_is_refused(self):
        # The identity is how a carrier finds its secret in the store, and
        # the secret is the address: without it there is nothing to dial.
        for bad in ({}, {"identity": ""}, {"identity": "   "},
                    {"identity": None}, {"identity": 7}):
            with self.subTest(bad=bad):
                entry = carrier_entry()
                if bad:
                    entry.update(bad)
                else:
                    del entry["identity"]
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(entry))
                message = str(caught.exception)
                self.assertIn("identity", message)
                # The value, not only the setting's name: a message that
                # says which key is wrong but not what it holds sends an
                # operator back to the file to guess what it read.
                self.assertIn(repr(bad["identity"] if bad else None), message)
                self.assertIn("gs-pi-01", message)

    def test_a_carrier_without_a_name_is_refused(self):
        # The index is the offending value here: with no name there is
        # nothing else to call the entry by, and `c2.gsocket_carrier[0]`
        # is what an operator can find in the file.
        for entries in ([{"identity": "pi-01"}],
                        [carrier_entry(), {"identity": "pi-02"}]):
            with self.subTest(count=len(entries)):
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(*entries))
                message = str(caught.exception)
                self.assertIn("name", message)
                self.assertIn("c2.gsocket_carrier[%d]" % (len(entries) - 1),
                              message)

    def test_a_beacon_port_outside_1_65535_is_refused(self):
        for bad in (0, -1, 65536, 99999, "8443", 8443.0, None, True):
            with self.subTest(beacon_port=bad):
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(carrier_entry(beacon_port=bad)))
                message = str(caught.exception)
                self.assertIn(repr(bad), message)
                self.assertIn("65535", message)

    def test_a_beacon_port_at_either_end_of_the_range_is_accepted(self):
        for good in (1, 65535):
            with self.subTest(beacon_port=good):
                specs = load_carriers(
                    config_with(carrier_entry(beacon_port=good)))
                self.assertEqual(specs[0].beacon_port, good)

    def test_a_wildcard_beacon_host_is_refused(self):
        # `-d <beacon_host>` is a destination to connect to, not an
        # address to bind. An operator who copies `bind_host: 0.0.0.0`
        # out of `c2.listeners` into this block has confused exactly the
        # two sides this module exists to keep apart.
        for bad in ("0.0.0.0", "", "   ", "*", "::"):
            with self.subTest(beacon_host=bad):
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(carrier_entry(beacon_host=bad)))
                message = str(caught.exception)
                self.assertIn("beacon_host", message)
                self.assertIn(repr(bad), message)

    def test_an_unknown_carrier_setting_is_refused_rather_than_ignored(self):
        # `local_port` in particular: it is a real setting on the *other*
        # side of this file, so it is the one somebody writes here.
        with self.assertRaises(ValueError) as caught:
            load_carriers(config_with(carrier_entry(local_port=16443)))
        message = str(caught.exception)
        self.assertIn("local_port", message)
        self.assertIn("c2.fallback.gsocket", message)

    def test_a_non_hex_sha256_is_refused(self):
        for bad in ("nothex", "a" * 63, "a" * 65, "zz" + "a" * 62, 7,
                    "a b" + "c" * 61):
            with self.subTest(sha256=bad):
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(carrier_entry(sha256=bad)))
                message = str(caught.exception)
                self.assertIn("sha256", message)
                self.assertIn(repr(bad), message)
                self.assertIn("gs-pi-01", message)

    def test_an_absent_or_empty_sha256_skips_the_check(self):
        # The same meaning `c2.sliver.sha256` has: empty is "do not
        # verify", not "verify against nothing".
        entry = carrier_entry()
        self.assertEqual(load_carriers(config_with(entry))[0].sha256, "")
        self.assertEqual(
            load_carriers(config_with(carrier_entry(sha256="")))[0].sha256, "")

    def test_a_block_that_is_not_a_list_is_refused(self):
        for bad in ({"identity": "pi-01"}, "pi-01", 7):
            with self.subTest(block=bad):
                with self.assertRaises(ValueError) as caught:
                    load_carriers({"c2": {"gsocket_carrier": bad}})
                self.assertIn("c2.gsocket_carrier", str(caught.exception))

    def test_an_entry_that_is_not_a_mapping_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            load_carriers(config_with(carrier_entry(), "pi-02"))
        message = str(caught.exception)
        self.assertIn("c2.gsocket_carrier[1]", message)
        self.assertIn("str", message)

    def test_two_carriers_may_share_one_beacon_socket(self):
        # Not a collision, unlike two listeners on one port: every
        # carrier forwards *into* the team server's beacon socket, so one
        # carrier per implant all naming 127.0.0.1:8443 is the normal
        # deployment and must not be refused.
        specs = load_carriers(config_with(
            carrier_entry(name="gs-a", identity="pi-01"),
            carrier_entry(name="gs-b", identity="pi-02")))
        self.assertEqual([spec.identity for spec in specs], ["pi-01", "pi-02"])


class TestLegBlock(unittest.TestCase):
    """`c2.fallback.gsocket`: this host as a client."""

    def test_leg_defaults_scheme_to_http(self):
        # Not https, and that is a fact about this repository rather than
        # a preference: `server.py`'s `--ssl` is `store_true` and off by
        # default, and every shipped `relay_url` is `http://`. The beacon
        # socket this leg's forward lands on speaks plain HTTP.
        self.assertEqual(LEG_DEFAULTS["scheme"], "http")
        self.assertEqual(validate_leg({})["scheme"], "http")
        self.assertEqual(validate_leg(None)["scheme"], "http")
        self.assertEqual(validate_leg(leg_block())["scheme"], "http")

    def test_the_leg_defaults_are_the_five_documented_values(self):
        # Asserted as values because Task 6's `beacon.py` cannot import
        # this module -- it is served to a target as source text and may
        # import only the standard library -- so it carries these five
        # numbers as a copy. Drift between the two ends is a forward that
        # lands on the wrong port.
        self.assertEqual(LEG_DEFAULTS, {
            "scheme": "http",
            "local_port": 16443,
            "restart_delay_seconds": 30,
            "max_restarts": 0,
            "ready_timeout_seconds": 20,
        })

    def test_a_missing_leg_block_is_not_an_error(self):
        for block in (None, {}):
            with self.subTest(block=block):
                leg = validate_leg(block)
                self.assertFalse(leg["enabled"])
                self.assertEqual(leg["secret_file"], "")
                self.assertEqual(leg["binary_path"], "")
                self.assertEqual(leg["sha256"], "")
                for key, value in LEG_DEFAULTS.items():
                    self.assertEqual(leg[key], value)

    def test_the_returned_block_does_not_share_the_defaults(self):
        leg = validate_leg({})
        leg["local_port"] = 1
        self.assertEqual(LEG_DEFAULTS["local_port"], 16443)
        self.assertEqual(validate_leg({})["local_port"], 16443)

    def test_an_explicit_value_survives_validation(self):
        leg = validate_leg(leg_block(
            sha256="b" * 64, scheme="https", local_port=20000,
            restart_delay_seconds=5, max_restarts=3,
            ready_timeout_seconds=45))
        self.assertEqual(leg, {
            "enabled": True,
            "secret_file": "/var/lib/raccoon/gsocket.key",
            "binary_path": "/opt/raccoon/bin/gs-netcat",
            "sha256": "b" * 64,
            "scheme": "https",
            "local_port": 20000,
            "restart_delay_seconds": 5,
            "max_restarts": 3,
            "ready_timeout_seconds": 45,
        })

    def test_the_leg_carries_a_sha256_for_the_binary_it_execs(self):
        # The implant verifies the `gs-netcat` it is about to exec with
        # its own copy of the carrier's check -- `beacon.py` may import
        # only the standard library, so it cannot share the server's --
        # and a copy with nowhere to read the expected digest from would
        # degrade to "the file exists and is executable" while claiming
        # parity with the real one. So the key exists on this side too,
        # is validated by the same checker, and is normalised the same
        # way.
        self.assertIn("sha256", validate_leg(leg_block()))
        self.assertEqual(
            validate_leg(leg_block(sha256="A" * 64))["sha256"], "a" * 64)
        for bad in ("nothex", "a" * 63, "a" * 65, 7, "a b" + "c" * 61):
            with self.subTest(sha256=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(sha256=bad))
                message = str(caught.exception)
                self.assertIn("sha256", message)
                self.assertIn(repr(bad), message)
                # Which block, so a refusal is never ambiguous between
                # the two that look alike.
                self.assertIn("c2.fallback.gsocket", message)

    def test_an_absent_leg_sha256_means_do_not_verify(self):
        # Never required, on either side: a deployment that has not
        # pinned a digest yet must still start. `None` is included
        # because a bare `sha256:` in YAML parses to it.
        for absent in ("", "   ", None):
            with self.subTest(sha256=absent):
                self.assertEqual(
                    validate_leg(leg_block(sha256=absent))["sha256"], "")
        self.assertEqual(validate_leg(leg_block())["sha256"], "")
        self.assertEqual(validate_leg({})["sha256"], "")
        self.assertEqual(validate_leg(None)["sha256"], "")

    def test_an_enabled_leg_without_a_secret_file_is_refused(self):
        for bad, shown in ((None, ""), ({"secret_file": ""}, ""),
                           ({"secret_file": "   "}, "   "),
                           ({"secret_file": None}, ""),
                           ({"secret_file": 7}, 7)):
            with self.subTest(bad=bad):
                block = leg_block()
                if bad is None:
                    del block["secret_file"]
                else:
                    block.update(bad)
                with self.assertRaises(ValueError) as caught:
                    validate_leg(block)
                message = str(caught.exception)
                self.assertIn("secret_file", message)
                self.assertIn(repr(shown), message)

    def test_a_disabled_leg_may_have_no_secret_file_yet(self):
        # The generator mints one secret file per build, so the block
        # shipped in `configs/raccoon.yaml` cannot name one: the same
        # rule `c2.encryption_key` follows, where the value is required
        # only while the fallback is enabled.
        leg = validate_leg({"enabled": False})
        self.assertEqual(leg["secret_file"], "")
        self.assertFalse(leg["enabled"])

    def test_an_unknown_leg_setting_is_refused_rather_than_ignored(self):
        # A setting silently dropped looks exactly like one that was
        # applied. `beacon_port` is the one worth naming twice: it is a
        # real setting on the *server* side of this file, so the refusal
        # says which block it belongs to rather than calling it a typo.
        for bad in ("local_prot", "bind_port", "secret", "beacon_port"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(**{bad: 1}))
                message = str(caught.exception)
                self.assertIn(bad, message)
        # And the key that exists on the other side is told so by name,
        # because "unknown setting" would send an operator looking for a
        # typo in a word they spelled correctly.
        with self.assertRaises(ValueError) as caught:
            validate_leg(leg_block(beacon_port=8443))
        self.assertIn("c2.gsocket_carrier", str(caught.exception))

    def test_no_secret_value_belongs_in_the_leg_block(self):
        # `gs-netcat -s <secret>` puts the credential in a world-readable
        # `ps` line, and a config file is pasted into tickets. The leg
        # names a file; `secret` is refused as an unknown key above, and
        # the accepted spelling is the path.
        leg = validate_leg(leg_block())
        self.assertNotIn("secret", leg)
        self.assertIn("secret_file", leg)

    def test_a_scheme_other_than_http_or_https_is_refused(self):
        for bad in ("ftp", "gs", "http://", "", "   ", None, 7, "htp"):
            with self.subTest(scheme=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(scheme=bad))
                message = str(caught.exception)
                self.assertIn(repr(bad), message)
                self.assertIn("http", message)

    def test_a_scheme_is_read_case_insensitively(self):
        # A URL scheme is case-insensitive, so "HTTPS" is unambiguous and
        # refusing it would be pedantry. It is normalised rather than
        # passed through, because Task 6 builds a URL out of it.
        self.assertEqual(validate_leg(leg_block(scheme="HTTPS"))["scheme"],
                         "https")
        self.assertEqual(validate_leg(leg_block(scheme=" Http "))["scheme"],
                         "http")

    def test_a_local_port_outside_1_65535_is_refused(self):
        for bad in (0, -1, 65536, "16443", None, True, 16443.0):
            with self.subTest(local_port=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(local_port=bad))
                message = str(caught.exception)
                self.assertIn(repr(bad), message)
                self.assertIn("65535", message)

    def test_a_disabled_leg_is_validated_as_strictly_as_an_enabled_one(self):
        for spoiled in (
                {"scheme": "ftp"},
                {"local_port": 0},
                {"binary_path": "gs-netcat"},
                {"secret_file": "gsocket.key"},
                {"restart_delay_seconds": 0},
                {"max_restarts": -1},
                {"ready_timeout_seconds": 0},
                {"nonsense": True},
        ):
            with self.subTest(spoiled=spoiled):
                block = {"enabled": False}
                block.update(spoiled)
                with self.assertRaises(ValueError):
                    validate_leg(block)

    def test_a_restart_delay_of_zero_is_refused(self):
        # Zero is a restart as fast as `gs-netcat` can fail, which is a
        # busy loop on the implant's CPU and a flood of joins on the
        # relay network -- both of them loud in exactly the place an
        # implant must be quiet.
        for bad in (0, -1, "30", None, True, 30.0):
            with self.subTest(restart_delay_seconds=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(restart_delay_seconds=bad))
                message = str(caught.exception)
                self.assertIn("restart_delay_seconds", message)
                self.assertIn(repr(bad), message)

    def test_max_restarts_of_zero_means_unlimited_and_is_accepted(self):
        # The meaning `c2.sliver.max_restarts` already has in this file.
        leg = validate_leg(leg_block(max_restarts=0))
        self.assertEqual(leg["max_restarts"], 0)
        for bad in (-1, "3", None, True, 3.0):
            with self.subTest(max_restarts=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(max_restarts=bad))
                message = str(caught.exception)
                self.assertIn("max_restarts", message)
                self.assertIn(repr(bad), message)

    def test_a_ready_timeout_of_zero_is_refused(self):
        # A zero timeout declares every carrier not-ready the instant it
        # is started, so the leg would never be used and nothing would
        # say why.
        for bad in (0, -1, "20", None, True, 20.0):
            with self.subTest(ready_timeout_seconds=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(leg_block(ready_timeout_seconds=bad))
                message = str(caught.exception)
                self.assertIn("ready_timeout_seconds", message)
                self.assertIn(repr(bad), message)

    def test_a_leg_block_that_is_not_a_mapping_is_refused(self):
        for bad in ([], "enabled", 7, True):
            with self.subTest(block=bad):
                with self.assertRaises(ValueError) as caught:
                    validate_leg(bad)
                self.assertIn("c2.fallback.gsocket", str(caught.exception))


class TestBothSides(unittest.TestCase):
    def test_a_relative_binary_path_is_refused(self):
        # The cwd on the implant is not ours to assume -- systemd gives a
        # unit `/`, and a shell started from an operator's home gives
        # something else again -- so "gs-netcat" is a different binary
        # depending on who started the process, or none at all.
        for bad in ("gs-netcat", "./gs-netcat", "bin/gs-netcat",
                    "../bin/gs-netcat", "~/gs-netcat"):
            with self.subTest(binary_path=bad):
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(carrier_entry(binary_path=bad)))
                self.assertIn(bad, str(caught.exception))
                # The leg, disabled, is held to it too: the value is
                # wrong now and switching the leg on will not fix it.
                with self.assertRaises(ValueError) as caught:
                    validate_leg({"enabled": False, "binary_path": bad})
                self.assertIn(bad, str(caught.exception))

    def test_an_enabled_leg_needs_a_binary_path(self):
        # `shown` is what the refusal must print: an absent key and an
        # explicit `None` both read as the empty string, which is what a
        # bare `binary_path:` in YAML means.
        for bad, shown in ((None, ""), ({"binary_path": ""}, ""),
                           ({"binary_path": "   "}, "   "),
                           ({"binary_path": None}, ""),
                           ({"binary_path": 7}, 7)):
            with self.subTest(bad=bad):
                block = leg_block()
                if bad is None:
                    del block["binary_path"]
                else:
                    block.update(bad)
                with self.assertRaises(ValueError) as caught:
                    validate_leg(block)
                message = str(caught.exception)
                self.assertIn("binary_path", message)
                self.assertIn(repr(shown), message)

    def test_a_carrier_needs_a_binary_path(self):
        for bad, shown in ((None, ""), ({"binary_path": ""}, ""),
                           ({"binary_path": "   "}, "   "),
                           ({"binary_path": None}, ""),
                           ({"binary_path": 7}, 7)):
            with self.subTest(bad=bad):
                entry = carrier_entry()
                if bad is None:
                    del entry["binary_path"]
                else:
                    entry.update(bad)
                with self.assertRaises(ValueError) as caught:
                    load_carriers(config_with(entry))
                message = str(caught.exception)
                self.assertIn("binary_path", message)
                self.assertIn(repr(shown), message)
                self.assertIn("gs-pi-01", message)

    def test_neither_side_is_asked_whether_the_binary_exists(self):
        # The carrier block is validated on the team server and the leg
        # block describes a path on someone else's hardware, so an
        # existence check would refuse a sound config for a file it
        # cannot see. The failure that matters arrives at exec time, from
        # the process that actually needs the binary.
        missing = "/nonexistent/definitely/not/here/gs-netcat"
        self.assertEqual(
            load_carriers(config_with(
                carrier_entry(binary_path=missing)))[0].binary_path,
            missing)
        self.assertEqual(
            validate_leg(leg_block(binary_path=missing))["binary_path"],
            missing)


if __name__ == "__main__":
    unittest.main()

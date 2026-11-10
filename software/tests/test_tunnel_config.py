#!/usr/bin/env python3
"""
Unit tests for how a tunnel is *configured*: baked into a build by the
generator, written into `configs/raccoon.yaml` for a host that runs the
endpoint on its own, and started there by systemd.

Four things these tests are careful about.

**Both generator routes are driven, not one.** `api_beacon_gen` and
`api_beacon_gist` each assemble their own `gen_cfg`, and a key added to
one of them is this repository's most frequent defect: `_obfuscate_layer`
and `_beacon_config_block` were both hoisted out of those two routes after
exactly that. So every generator assertion here runs against both, and the
gist route is exercised rather than inspected -- `gh` is replaced and what
the route would have uploaded is read back out of the file it hands to
`gh gist create`.

**The artifact is unwrapped, not exec'd.** `_obfuscate_layer`'s output has
one exact shape, so the wrapper is matched and `zlib.decompress`ed instead
of being executed in this process. The config the build carries is then
read out of the blob the bootstrap decodes. That is the delivered artifact
and not a restatement of the generator: if the layer shape changes, the
match fails loudly rather than quietly testing nothing.

**Two builds, through the route, and the store is asked.** A per-build
identity that came from a counter would differ between two calls in one
test and tell us nothing. So the identity test generates twice through the
route and then asks the `KeyStore` on disk whether it holds both, and
whether `identity_for` maps each PSK to its own build.

**The PSK test proves a refusal, not an absence.** A `psk` key is put in a
YAML fixture and the loader is required to raise with
`RACCOON_TUNNEL_PSK` in the message. "The shipped file happens not to have
one" would pass against a loader that read it happily.

No port is hardcoded: the generator takes the tunnel server's port in the
request body, and the numbers in the shipped YAML are a file on disk that
nothing in this file binds.
"""

import base64
import json
import os
import re
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import yaml

from software.c2 import beacon as beacon_mod
from software.c2 import server as server_mod
from software.c2.beacon import (
    TunnelEndpoint,
    beacon_config_from_fallback,
    tunnel_config_from_yaml,
    tunnel_config_problem,
    tunnel_mode_problem,
)
from software.c2.server import ServerCrypto, create_app
from software.c2.tunnel.keys import KeyStore

_REPO = Path(__file__).resolve().parent.parent.parent
_SHIPPED_YAML = _REPO / "configs" / "raccoon.yaml"
_TUNNEL_UNIT = _REPO / "services" / "raccoon-tunnel.service"

_TOKEN = "test-token"
_AUTH = {"Authorization": "Bearer " + _TOKEN}

# Exactly what `_obfuscate_layer` emits, so an unwrap that stops matching
# fails this file rather than passing against something it never read.
_LAYER = re.compile(
    r'^import base64 as (\w+),zlib;'
    r"globals\(\)\['_src'\]=zlib\.decompress\("
    r"\1\.b64decode\('([A-Za-z0-9+/=]*)'\)\);"
    r'exec\(_src\)$')

# The base64 JSON blob `_beacon_config_block` has the bootstrap decode.
_BAKED = re.compile(r'_j\.loads\(_b64\.b64decode\("([A-Za-z0-9+/=]*)"\)')

# The eight fields a tunnel block carries, from the generator and from the
# YAML alike. Written here once; both paths are asserted against it.
_TUNNEL_FIELDS = ("enabled", "server", "port", "public_key", "psk",
                  "identity", "keepalive_seconds", "allow_slow_crypto")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _innermost(code):
    """The source inside however many `_obfuscate_layer` wrappers."""
    while True:
        match = _LAYER.match(code)
        if match is None:
            return code
        code = zlib.decompress(
            base64.b64decode(match.group(2))).decode("utf-8")


def _baked_config(artifact):
    """The `gen_cfg` a generated artifact carries."""
    match = _BAKED.search(artifact)
    assert match is not None, "the artifact carries no config blob"
    return json.loads(base64.b64decode(match.group(1)).decode("utf-8"))


def _yaml_text(tunnel_lines):
    """A minimal drop-box config with the given `c2.tunnel` body."""
    return ("c2:\n"
            "  enabled: true\n"
            "  encryption_key: \"%s\"\n"
            "  fallback:\n"
            "    enabled: true\n"
            "  tunnel:\n%s" % (_b64(os.urandom(32)), tunnel_lines))


class _GeneratorCase(unittest.TestCase):
    """A team server on the test client, and both generator routes.

    `data_dir` is a fresh temporary directory per test, because that is
    where the generator's `KeyStore` lives and a store shared between
    tests would make "this build is registered" mean "some build is".
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name) / "data"
        self.app = create_app(ServerCrypto(os.urandom(32)), _TOKEN,
                              self.data_dir)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        pending = server_mod._pending_gists
        before = dict(pending)
        self.addCleanup(lambda: (pending.clear(), pending.update(before)))

    # ── the two routes ──

    def request_body(self, tunnel=None):
        body = {"c2_url": "http://127.0.0.1:1/api/v1/beacon", "layers": 1}
        if tunnel is not None:
            body["tunnel"] = tunnel
        return body

    def post_gen(self, tunnel=None):
        response = self.client.post("/api/server/beacon-gen",
                                    json=self.request_body(tunnel),
                                    headers=_AUTH)
        return response

    def post_gist(self, tunnel=None):
        """The gist route, with `gh` replaced and its upload captured."""
        uploaded = {}

        def fake_run(args, **kwargs):
            import subprocess

            args = list(args)
            if args[:2] == ["gh", "auth"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:3] == ["gh", "gist", "create"]:
                uploaded["stage"] = Path(args[-1]).read_text(encoding="utf-8")
                return subprocess.CompletedProcess(
                    args, 0, "https://gist.github.com/u/deadbeef\n", "")
            if args[:2] == ["gh", "api"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            raise AssertionError("unexpected command: %r" % (args,))

        with mock.patch.object(server_mod.subprocess, "run", fake_run):
            response = self.client.post("/api/server/beacon-gist",
                                        json=self.request_body(tunnel),
                                        headers=_AUTH)
        self._uploaded = uploaded.get("stage")
        return response

    def generate(self, route, tunnel=None):
        """`(response_json, gen_cfg)` for one build from one route."""
        response = getattr(self, "post_" + route)(tunnel)
        self.assertEqual(response.status_code, 200, response.data[:400])
        body = response.get_json()
        if route == "gen":
            prefix = 'python3 -c "'
            one = body["oneliner_unix"]
            self.assertTrue(one.startswith(prefix) and one.endswith('"'),
                            one[:80])
            stage = one[len(prefix):-1]
        else:
            self.assertIsNotNone(self._uploaded,
                                 "the gist route uploaded nothing")
            stage = self._uploaded
        return body, _baked_config(_innermost(stage))

    def store(self):
        return KeyStore(server_mod._tunnel_keystore_path(self.data_dir))

    def asked_for(self, port=8446, **overrides):
        tunnel = {"enabled": True, "server": "tunnel.example.com",
                  "port": port}
        tunnel.update(overrides)
        return tunnel


class TestTheGeneratorBakesATunnelBlock(_GeneratorCase):
    """What a build carries when the request asks for a tunnel."""

    def test_beacon_gen_bakes_a_tunnel_block_when_asked(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                asked = self.asked_for(keepalive_seconds=45,
                                       allow_slow_crypto=True)
                body, gen_cfg = self.generate(route, asked)
                tunnel = gen_cfg.get("tunnel")
                self.assertIsInstance(
                    tunnel, dict,
                    "the %s route baked no tunnel block" % route)
                for field in _TUNNEL_FIELDS:
                    self.assertIn(field, tunnel,
                                  "the baked block has no %r" % field)

                self.assertTrue(tunnel["enabled"])
                self.assertEqual(tunnel["server"], asked["server"])
                self.assertEqual(tunnel["port"], asked["port"])
                self.assertEqual(tunnel["keepalive_seconds"], 45)
                self.assertTrue(tunnel["allow_slow_crypto"])

                # The build is runnable as an endpoint, which is the only
                # thing that makes the block worth baking.
                config = {"c2": {"tunnel": tunnel}}
                self.assertIsNone(tunnel_mode_problem(config))
                endpoint = TunnelEndpoint(config)
                self.assertEqual(endpoint.identity, tunnel["identity"])
                self.assertEqual(endpoint.port, asked["port"])

                # The operator is told which build this is -- there is
                # otherwise no record outside the key store -- and is not
                # handed the credential back in a JSON response.
                self.assertEqual(body.get("tunnel_identity"),
                                 tunnel["identity"])
                self.assertNotIn(tunnel["psk"], json.dumps(body),
                                 "the response carries the build's PSK")

    def test_beacon_gen_registers_the_psk_with_the_key_store(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                _body, gen_cfg = self.generate(route, self.asked_for())
                tunnel = gen_cfg["tunnel"]
                store = self.store()

                psk = base64.b64decode(tunnel["psk"])
                self.assertEqual(len(psk), 32)
                self.assertEqual(
                    store.identity_for(psk), tunnel["identity"],
                    "the %s route baked a PSK the server does not hold, so "
                    "the build could never authenticate" % route)
                self.assertEqual(
                    tunnel["public_key"], _b64(store.static_public()),
                    "the build carries a public key that is not this "
                    "deployment's, so its handshake cannot complete")

    def test_each_generated_build_gets_a_distinct_identity_and_psk(self):
        # Through the route twice, and then asked of the store on disk. A
        # counter would differ between two calls in one test and prove
        # nothing about two builds; what matters is that the server holds
        # both credentials at once and can tell them apart.
        first = self.generate("gen", self.asked_for())[1]["tunnel"]
        second = self.generate("gist", self.asked_for())[1]["tunnel"]

        self.assertNotEqual(first["identity"], second["identity"])
        self.assertNotEqual(first["psk"], second["psk"])

        store = self.store()
        held = {build["identity"] for build in store.builds()}
        self.assertEqual(held, {first["identity"], second["identity"]},
                         "the store does not hold exactly the two builds "
                         "that were generated")
        for build in (first, second):
            self.assertEqual(
                store.identity_for(base64.b64decode(build["psk"])),
                build["identity"],
                "a PSK does not map back to its own build")

    def test_a_build_without_a_tunnel_block_still_runs_as_a_plain_beacon(self):
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                _body, gen_cfg = self.generate(route)
                self.assertFalse(
                    gen_cfg.get("tunnel"),
                    "a build nobody asked a tunnel of carries one")

                # The bootstrap's own two predicates: nothing is wrong with
                # this config, and it cannot be run as an endpoint.
                config = {"c2": {"tunnel": gen_cfg.get("tunnel")}}
                self.assertIsNone(tunnel_config_problem(config))
                self.assertIsNotNone(tunnel_mode_problem(config))

                # And no credential was minted for a build that cannot use
                # one: a store littered with PSKs no build holds is a
                # candidate list every handshake has to walk.
                self.assertEqual(self.store().builds(), [])

    def test_the_request_may_not_supply_the_psk_or_the_identity(self):
        # Both are the generator's to mint, per build. A request that
        # named either would be an operator expecting a build the server
        # has not registered; accepting and ignoring it is how that goes
        # unnoticed until the handshake fails.
        for field in ("psk", "identity", "public_key"):
            for route in ("gen", "gist"):
                with self.subTest(field=field, route=route):
                    asked = self.asked_for(**{field: "supplied-by-hand"})
                    response = getattr(self, "post_" + route)(asked)
                    self.assertEqual(response.status_code, 400,
                                     response.data[:400])
                    error = response.get_json()["error"]
                    self.assertIn(field, error)
                    self.assertEqual(self.store().builds(), [])


    def test_a_damaged_key_store_is_the_servers_fault_and_says_so(self):
        # Not a 400. A request that was fine, answered as if it were not,
        # sends the operator to look at their own form while the message
        # names a file on the team server.
        path = server_mod._tunnel_keystore_path(self.data_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        for route in ("gen", "gist"):
            with self.subTest(route=route):
                response = getattr(self, "post_" + route)(self.asked_for())
                self.assertEqual(response.status_code, 500,
                                 response.data[:400])
                self.assertIn(str(path), response.get_json()["error"])

    def test_a_gist_that_never_uploaded_leaves_no_credential_behind(self):
        # The gist route registers the build before `gh` has uploaded
        # anything. Every PSK in the store is tried on every incoming
        # handshake, so one left there for a build nobody received is a
        # candidate walked for ever.
        import subprocess

        def fake_run(args, **kwargs):
            args = list(args)
            if args[:2] == ["gh", "auth"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:3] == ["gh", "gist", "create"]:
                return subprocess.CompletedProcess(args, 1, "", "no network")
            raise AssertionError("unexpected command: %r" % (args,))

        with mock.patch.object(server_mod.subprocess, "run", fake_run):
            response = self.client.post("/api/server/beacon-gist",
                                        json=self.request_body(
                                            self.asked_for()),
                                        headers=_AUTH)
        self.assertEqual(response.status_code, 500, response.data[:400])
        self.assertEqual(self.store().builds(), [],
                         "the undelivered build is still registered")


    def test_a_gist_upload_that_times_out_leaves_no_credential_behind(self):
        # The live failure mode the guard above was written for and
        # missed: `gh gist create` carries `timeout=30`, which raises
        # rather than returning a non-zero code, so a check on the return
        # code alone never runs.
        import subprocess

        def fake_run(args, **kwargs):
            args = list(args)
            if args[:2] == ["gh", "auth"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[:3] == ["gh", "gist", "create"]:
                raise subprocess.TimeoutExpired(args, 30)
            raise AssertionError("unexpected command: %r" % (args,))

        with mock.patch.object(server_mod.subprocess, "run", fake_run):
            response = self.client.post("/api/server/beacon-gist",
                                        json=self.request_body(
                                            self.asked_for()),
                                        headers=_AUTH)
        self.assertEqual(response.status_code, 504, response.data[:400])
        self.assertEqual(self.store().builds(), [],
                         "a build whose upload timed out is still "
                         "registered")


class TestTheYamlPath(unittest.TestCase):
    """`c2.tunnel` read from a config file, for a host with no beacon.

    Goal 3 of this work: the endpoint runs where systemd starts it and
    nothing hands it a config block. `beacon_config_from_fallback` is the
    one place a `c2` block becomes a beacon config, so the tunnel comes
    out of the same function in the same shape the generator bakes.
    """

    def fixture(self, tunnel_lines):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "raccoon.yaml"
        path.write_text(_yaml_text(tunnel_lines), encoding="utf-8")
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def enabled_lines(self, public_key, **extra):
        lines = ["    enabled: true",
                 "    server: \"tunnel.example.com\"",
                 "    port: 8446",
                 "    public_key: \"%s\"" % public_key,
                 "    identity: \"pi-dropbox\""]
        for key, value in extra.items():
            lines.append("    %s: %s" % (key, json.dumps(value)))
        return "\n".join(lines) + "\n"

    def test_fallback_config_reads_c2_tunnel_from_the_yaml(self):
        public = _b64(os.urandom(32))
        psk = _b64(os.urandom(32))
        config = self.fixture(self.enabled_lines(public,
                                                 keepalive_seconds=45,
                                                 allow_slow_crypto=True))

        built = beacon_config_from_fallback(
            config["c2"], env={beacon_mod._TUNNEL_PSK_ENV: psk})
        tunnel = built["c2"]["tunnel"]

        for field in _TUNNEL_FIELDS:
            self.assertIn(field, tunnel,
                          "the block built from the YAML has no %r" % field)
        self.assertTrue(tunnel["enabled"])
        self.assertEqual(tunnel["server"], "tunnel.example.com")
        self.assertEqual(tunnel["port"], 8446)
        self.assertEqual(tunnel["public_key"], public)
        self.assertEqual(tunnel["identity"], "pi-dropbox")
        self.assertEqual(tunnel["keepalive_seconds"], 45)
        self.assertTrue(tunnel["allow_slow_crypto"])
        self.assertEqual(tunnel["psk"], psk)

        # The same shape the generator bakes: runnable without anything
        # else being handed to it.
        self.assertIsNone(tunnel_mode_problem(built))
        endpoint = TunnelEndpoint(built)
        self.assertEqual(endpoint.identity, "pi-dropbox")

        # The beacon side of the file is untouched by any of that.
        self.assertEqual(built["c2"]["https"], {})

    def test_no_tunnel_block_in_the_yaml_is_not_an_error(self):
        # Every deployment that predates this feature has none of this,
        # and all of them have to keep starting.
        built = beacon_config_from_fallback({"fallback": {"enabled": True}},
                                            env={})
        self.assertIsNone(built["c2"].get("tunnel"))
        self.assertIsNone(tunnel_config_problem(built))

    def test_the_psk_is_not_read_from_the_yaml(self):
        # The refusal, not the absence. A loader that read a `psk` key
        # happily would pass any test that only looked at the shipped
        # file, because the shipped file does not have one.
        public = _b64(os.urandom(32))
        psk = _b64(os.urandom(32))
        config = self.fixture(
            self.enabled_lines(public) + "    psk: \"%s\"\n" % psk)

        with self.assertRaises(ValueError) as caught:
            tunnel_config_from_yaml(
                config["c2"], env={beacon_mod._TUNNEL_PSK_ENV: psk})
        message = str(caught.exception)
        self.assertIn("c2.tunnel.psk", message)
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV, message,
                      "the refusal does not say where the PSK should come "
                      "from instead")
        self.assertNotIn(psk, message, "the refusal quotes the secret")

    def test_a_psk_key_is_refused_even_while_the_tunnel_is_disabled(self):
        # The listeners' posture: a disabled block is validated exactly as
        # strictly as an enabled one, because a secret that waits in a
        # config file until somebody switches the tunnel on has chosen the
        # worst possible moment to be found.
        config = self.fixture("    enabled: false\n    psk: \"abc\"\n")
        with self.assertRaises(ValueError) as caught:
            tunnel_config_from_yaml(config["c2"], env={})
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV, str(caught.exception))

    def test_an_enabled_tunnel_with_no_psk_in_the_environment_is_refused(self):
        config = self.fixture(self.enabled_lines(_b64(os.urandom(32))))
        with self.assertRaises(ValueError) as caught:
            tunnel_config_from_yaml(config["c2"], env={})
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV, str(caught.exception))

    def test_the_psk_comes_from_the_real_environment_by_default(self):
        # `env=` is a seam for the tests above; the deployed path is
        # `os.environ`, and a default that read something else would make
        # every one of them prove nothing about the Pi.
        psk = _b64(os.urandom(32))
        config = self.fixture(self.enabled_lines(_b64(os.urandom(32))))
        with mock.patch.dict(os.environ,
                             {beacon_mod._TUNNEL_PSK_ENV: psk}, clear=False):
            built = beacon_config_from_fallback(config["c2"])
        self.assertEqual(built["c2"]["tunnel"]["psk"], psk)

    def test_a_half_filled_block_is_refused_where_the_config_is_loaded(self):
        # `tunnel_config_problem`'s docstring says it is asked where the
        # config is loaded. This is that place: a block that cannot work
        # is named by the field that is wrong, rather than becoming an
        # endpoint that retries a connection it can never make.
        lines = self.enabled_lines(_b64(os.urandom(32)))
        lines = lines.replace("    server: \"tunnel.example.com\"\n",
                              "    server: \"\"\n")
        config = self.fixture(lines)
        with self.assertRaises(ValueError) as caught:
            tunnel_config_from_yaml(
                config["c2"], env={beacon_mod._TUNNEL_PSK_ENV:
                                   _b64(os.urandom(32))})
        self.assertIn("c2.tunnel.server", str(caught.exception))

    def test_a_tunnel_it_cannot_run_does_not_cost_the_host_its_beacon(self):
        """The convenience does not get to take the access with it.

        `tunnel_config_from_yaml` refuses; `beacon_config_from_fallback`
        is the function `main.py` and `beacon_standalone.py` build their
        beacon from, and a drop-box that stopped calling home over a typo
        in a block nobody had switched on yet would be a box lost. So the
        block is left out and the reason is kept where the operator's own
        question will find it.
        """
        lines = self.enabled_lines(_b64(os.urandom(32)))
        lines = lines.replace("    port: 8446\n", "    port: 0\n")
        config = self.fixture(lines)

        with self.assertLogs(beacon_mod.logger, level="ERROR") as logged:
            built = beacon_config_from_fallback(
                config["c2"], env={beacon_mod._TUNNEL_PSK_ENV:
                                   _b64(os.urandom(32))})

        self.assertIsNone(built["c2"].get("tunnel"),
                          "an unusable tunnel block reached the beacon")
        self.assertEqual(built["c2"]["dns"], {})
        self.assertIn("c2.tunnel.port", "\n".join(logged.output),
                      "the reason the block was dropped was not logged")
        self.assertIn("c2.tunnel.port", built["c2"]["tunnel_problem"],
                      "the reason was not kept for the consumer that asks")

    def test_a_psk_in_the_file_reaches_the_operator_who_tasks_tunnel_start(self):
        """The case that otherwise has no channel at all.

        A Sliver-primary or `fallback.enabled: false` drop-box never
        reaches `beacon_config_from_fallback`, and when it does the ERROR
        goes to a rotating log file rather than anywhere an operator is
        looking. `tunnel start` is the question they ask, so that is where
        the reason has to be -- and it has to be the real one: the generic
        arm of `tunnel_mode_problem` tells them to generate a build with
        the tunnel enabled, which is not what is wrong and not something
        they can do about a key in a YAML file.
        """
        psk = _b64(os.urandom(32))
        config = self.fixture(
            self.enabled_lines(_b64(os.urandom(32)))
            + "    psk: \"%s\"\n" % psk)
        with self.assertLogs(beacon_mod.logger, level="ERROR"):
            built = beacon_config_from_fallback(
                config["c2"], env={beacon_mod._TUNNEL_PSK_ENV: psk})

        # The only block there was is the one holding the file's secret,
        # so it must not be passed on: `tunnel start` would dial with the
        # value this rule exists to refuse.
        self.assertIsNone(built["c2"].get("tunnel"))

        answer = beacon_mod.Beacon(built)._tunnel_start()
        self.assertIn("c2.tunnel.psk", answer)
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV, answer)
        self.assertNotIn(
            "Generate the build with the tunnel enabled", answer,
            "the operator was told to generate a build for a tunnel that "
            "came from a config file")
        self.assertNotIn(psk, answer, "the answer quotes the secret")

    def test_a_build_with_no_tunnel_still_gets_the_generate_a_build_advice(self):
        # The other arm, which is correct for the case it is for: an
        # artifact generated before anybody asked for a tunnel. Carrying
        # the file's reason must not have replaced it.
        built = beacon_config_from_fallback(
            {"encryption_key": _b64(os.urandom(32)),
             "fallback": {"enabled": True}}, env={})
        self.assertIsNone(built["c2"].get("tunnel_problem"))

        answer = beacon_mod.Beacon(built)._tunnel_start()
        self.assertIn("Generate the build with the tunnel enabled", answer)


class TestTheShippedConfig(unittest.TestCase):
    """What a fresh checkout's `configs/raccoon.yaml` says."""

    @classmethod
    def setUpClass(cls):
        cls.text = _SHIPPED_YAML.read_text(encoding="utf-8")
        cls.shipped = yaml.safe_load(cls.text)

    def test_shipped_yaml_has_the_tunnel_disabled(self):
        c2 = self.shipped["c2"]
        for block in ("tunnel", "tunnel_server"):
            with self.subTest(block=block):
                self.assertIn(block, c2,
                              "the shipped file has no c2.%s block" % block)
                self.assertFalse(
                    c2[block].get("enabled"),
                    "c2.%s ships enabled; a fresh checkout would dial out "
                    "or open a socket nobody asked for" % block)

        # And it goes through the loader without a word, which a block
        # with a typo waiting in it would not.
        built = beacon_config_from_fallback(c2, env={})
        self.assertFalse(built["c2"]["tunnel"]["enabled"])

    def test_the_shipped_tunnel_block_carries_no_psk(self):
        self.assertNotIn("psk", self.shipped["c2"]["tunnel"])
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV, self.text,
                      "the file does not say where the PSK comes from")

    def test_the_two_yaml_blocks_say_which_side_they_are_in_a_comment(self):
        # `c2.tunnel` and `c2.tunnel_server` look alike and mean opposite
        # things, exactly as `c2.fallback` and `c2.listeners` do: one
        # dials out, the other opens a socket. The key names do not say
        # which, so each block states its side in words above itself.
        # Markers put there to be found, following the test the listener
        # pair already has.
        client = "THIS HOST AS A TUNNEL CLIENT"
        server = "THIS HOST AS A TUNNEL SERVER"

        self.assertEqual(self.text.count(client), 1,
                         "the tunnel client-side marker is not there "
                         "exactly once")
        self.assertEqual(self.text.count(server), 1,
                         "the tunnel server-side marker is not there "
                         "exactly once")
        self.assertLess(self.text.index(client),
                        self.text.index("  tunnel:"),
                        "the client marker does not precede the block it "
                        "describes")
        self.assertLess(self.text.index("  tunnel:"),
                        self.text.index(server),
                        "the two markers do not bracket their own blocks")
        self.assertLess(self.text.index(server),
                        self.text.index("  tunnel_server:"),
                        "the server marker does not precede the block it "
                        "describes")

    def test_the_listener_markers_are_still_unique(self):
        # The listener pair's own test asserts each of its markers appears
        # exactly once. Two more blocks that mean opposite things is
        # precisely the temptation to reuse those two strings, which would
        # break that test for a reason that reads as unrelated.
        for marker in ("THIS HOST AS A CLIENT", "THIS HOST AS A SERVER"):
            self.assertEqual(self.text.count(marker), 1, marker)


class TestTheSystemdUnit(unittest.TestCase):
    """`services/raccoon-tunnel.service`: the endpoint with no beacon above it."""

    @classmethod
    def setUpClass(cls):
        cls.text = _TUNNEL_UNIT.read_text(encoding="utf-8")
        cls.directives = "\n".join(
            line for line in cls.text.splitlines()
            if line.strip() and not line.strip().startswith("#"))

    def test_systemd_unit_references_an_environment_file_and_not_a_literal_psk(self):
        self.assertIn("EnvironmentFile=", self.directives,
                      "the endpoint has nowhere to get its PSK")
        self.assertNotIn("%s=" % beacon_mod._TUNNEL_PSK_ENV, self.directives,
                         "the PSK is written into the unit file, which is "
                         "world-readable")

        exec_lines = [line for line in self.directives.splitlines()
                      if line.startswith("ExecStart")]
        self.assertTrue(exec_lines, "the unit starts nothing")
        for line in exec_lines:
            for banned in (beacon_mod._TUNNEL_PSK_ENV, "--psk",
                           "RACCOON_KEY=", "--key"):
                self.assertNotIn(banned, line,
                                 "the unit puts %s where ps can read it"
                                 % banned)

    def test_the_unit_starts_the_endpoint_and_not_the_tunnel_server(self):
        # The two look alike and mean opposite things. A drop-box that
        # started the server side would open a socket and hold the PSKs,
        # which is the inversion this project files under its own package
        # on purpose.
        self.assertIn("software.c2.tunnel_standalone", self.directives)
        self.assertNotIn("-m software.c2.tunnel ", self.directives)

    def test_the_module_the_unit_names_exists_and_refuses_a_bare_config(self):
        from software.c2 import tunnel_standalone

        self.assertTrue(hasattr(tunnel_standalone, "main"))
        # No tunnel configured is a refusal with a reason, not a process
        # that dials nothing in a loop.
        problem = tunnel_mode_problem(
            beacon_config_from_fallback({"fallback": {"enabled": True}},
                                        env={}))
        self.assertIsNotNone(problem)
        self.assertIn("c2.tunnel", problem)


class TestTheStandaloneEndpoint(unittest.TestCase):
    """`software.c2.tunnel_standalone`: the endpoint with nothing above it.

    Goal 3 of this work, proved rather than asserted: a config file, a
    `RACCOON_TUNNEL_PSK` in the environment, a real `TunnelServer`, and a
    child process that connects to it as a named endpoint. No beacon is
    involved at any point.

    The child is `python -c`, not `-m`, only so that `CONFIG_PATHS` can be
    pointed at a temporary file: that list is `beacon_standalone`'s and
    neither runner takes a config path on its command line. Everything
    else is the deployed path, `main()` included.
    """

    # The range the server assigns loopback SOCKS ports from. Inert here:
    # this task records an assignment in a JSON file and binds nothing,
    # and the server's own port is 0 and read back. **A later task binds
    # these**, and when it does this pair stops being two numbers and
    # becomes a hundred fixed loopback ports a test would take -- so the
    # no-hardcoded-port rule has to be applied to it again then, not
    # assumed to have been settled here.
    _PORT_RANGE = (40400, 40499)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def yaml_at(self, lines):
        path = self.root / "raccoon.yaml"
        path.write_text(_yaml_text(lines), encoding="utf-8")
        return path

    def run_main(self, config_path, env_psk=None, timeout=60):
        """`main()` in a child; returns the finished process."""
        import subprocess

        code = ("import software.c2.beacon_standalone as _bs;"
                "_bs.CONFIG_PATHS=[%r];"
                "import software.c2.tunnel_standalone as _ts;"
                "raise SystemExit(_ts.main())" % str(config_path))
        env = dict(os.environ, PYTHONPATH=str(_REPO))
        env.pop(beacon_mod._TUNNEL_PSK_ENV, None)
        if env_psk is not None:
            env[beacon_mod._TUNNEL_PSK_ENV] = env_psk
        return subprocess.run([sys.executable, "-c", code],
                              cwd=str(_REPO), env=env, timeout=timeout,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    def test_a_config_with_no_tunnel_is_refused_with_a_reason(self):
        done = self.run_main(self.yaml_at("    enabled: false\n"))
        self.assertEqual(done.returncode, 1)
        message = done.stderr.decode("utf-8", "replace")
        self.assertIn("c2.tunnel", message)
        self.assertIn("Refusing to start", message)

    def test_a_psk_in_the_file_is_refused_by_the_runner_too(self):
        path = self.yaml_at("    enabled: false\n    psk: \"abc\"\n")
        done = self.run_main(path)
        self.assertEqual(done.returncode, 1)
        self.assertIn(beacon_mod._TUNNEL_PSK_ENV,
                      done.stderr.decode("utf-8", "replace"))

    def test_systemd_can_run_the_endpoint_with_no_beacon_above_it(self):
        import subprocess
        import time

        from software.c2.tunnel.server import TunnelServer

        store = KeyStore(self.root / "keys.json")
        psk = os.urandom(32)
        store.register_build("pi-dropbox", psk)
        server = TunnelServer(store, "127.0.0.1", 0, self._PORT_RANGE,
                              str(self.root / "ports.json"),
                              keepalive_interval=30.0, idle_timeout=30.0,
                              handshake_timeout=20.0, session_timeout=30.0)
        server.start()
        self.addCleanup(server.stop)

        path = self.yaml_at(
            "    enabled: true\n"
            "    server: \"127.0.0.1\"\n"
            "    port: %d\n"
            "    public_key: \"%s\"\n"
            "    identity: \"pi-dropbox\"\n"
            # This machine may have no libcrypto, and a tunnel on the slow
            # path is still a tunnel; the refusal is Task 7's test.
            "    allow_slow_crypto: true\n"
            % (server.port, _b64(store.static_public())))

        code = ("import software.c2.beacon_standalone as _bs;"
                "_bs.CONFIG_PATHS=[%r];"
                "import software.c2.tunnel_standalone as _ts;"
                "raise SystemExit(_ts.main())" % str(path))
        env = dict(os.environ, PYTHONPATH=str(_REPO))
        env[beacon_mod._TUNNEL_PSK_ENV] = _b64(psk)
        child = subprocess.Popen([sys.executable, "-c", code],
                                 cwd=str(_REPO), env=env,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.stderr.close)
        self.addCleanup(child.wait, 30)
        self.addCleanup(child.kill)

        def connected():
            return any(row["identity"] == "pi-dropbox"
                       and row["state"] == "connected"
                       for row in server.endpoints())

        deadline = time.time() + 60.0
        while time.time() < deadline and not connected():
            if child.poll() is not None:
                self.fail("the runner exited with %s instead of connecting; "
                          "stderr: %s"
                          % (child.returncode,
                             child.stderr.read().decode("utf-8", "replace")))
            time.sleep(0.05)
        self.assertTrue(connected(),
                        "the endpoint never registered, so a host with only "
                        "a config file and an environment variable cannot "
                        "run the tunnel")
        row = [r for r in server.endpoints()
               if r["identity"] == "pi-dropbox"][0]
        self.assertTrue(row["port"], "the endpoint was issued no SOCKS port")


class TestTheTwoPathsAgree(unittest.TestCase):
    """One shape, from the generator and from the YAML.

    The endpoint reads one block. If the two producers disagreed about a
    field name, one of the two deployments would be broken and only the
    other is covered by the tests above.
    """

    def test_both_producers_emit_the_same_field_names(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        data_dir = Path(tmp.name) / "data"
        app = create_app(ServerCrypto(os.urandom(32)), _TOKEN, data_dir)
        app.config["TESTING"] = True
        response = app.test_client().post(
            "/api/server/beacon-gen",
            json={"c2_url": "http://127.0.0.1:1/x", "layers": 1,
                  "tunnel": {"enabled": True, "server": "t.example.com",
                             "port": 8446}},
            headers=_AUTH)
        self.assertEqual(response.status_code, 200, response.data[:400])
        prefix = 'python3 -c "'
        stage = response.get_json()["oneliner_unix"][len(prefix):-1]
        baked = _baked_config(_innermost(stage))["tunnel"]

        from_yaml = tunnel_config_from_yaml(
            {"tunnel": {"enabled": True, "server": "t.example.com",
                        "port": 8446, "public_key": _b64(os.urandom(32)),
                        "identity": "pi-dropbox"}},
            env={beacon_mod._TUNNEL_PSK_ENV: _b64(os.urandom(32))})

        self.assertEqual(sorted(baked), sorted(from_yaml))
        self.assertEqual(sorted(baked), sorted(_TUNNEL_FIELDS))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The end-to-end lab's topology, judged without Docker.

`software/tests/lab/` holds the containers and networks for a Linux
end-to-end run, and the point of it is that a beacon's transports fail
*because they do not route*. That property lives entirely in the compose
file -- which service is on which network -- so it can be checked by
reading the file, on every machine, in the normal suite. What cannot be
checked here is that Docker honours it; the driver asserts that from
inside the beacon container after it has severed the network.

These read the compose file with PyYAML and make no assumption about how
it spells a list: a test that passed only for one spelling would be
guarding the spelling.
"""

import importlib.util
import ipaddress
import re
import shlex
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import yaml

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "software" / "tests" / "lab"
LAB_COMPOSE = LAB / "docker-compose.yml"
SHIPPED_COMPOSE = REPO / "software" / "c2" / "docker-compose.yml"
SHIPPED_LISTENER_DOCKERFILE = (
    REPO / "software" / "c2" / "listeners" / "Dockerfile")

sys.path.insert(0, str(REPO))


def _load(path):
    with open(path) as handle:
        return yaml.safe_load(handle)


def _networks(service):
    """Network name -> its per-service settings, whichever form it is in."""
    declared = service.get("networks") or {}
    if isinstance(declared, dict):
        return {name: (settings or {}) for name, settings in declared.items()}
    return {name: {} for name in declared}


def _published(compose):
    """Every published port as (service, host_ip, target, protocol)."""
    found = []
    for name, service in compose["services"].items():
        for port in service.get("ports") or []:
            if isinstance(port, dict):
                found.append((name, port.get("host_ip", ""),
                              int(port["target"]),
                              port.get("protocol", "tcp")))
                continue
            text = str(port)
            text, _, protocol = text.partition("/")
            parts = text.split(":")
            host_ip = parts[0] if len(parts) == 3 else ""
            found.append((name, host_ip, int(parts[-1]), protocol or "tcp"))
    return found


def _command(service):
    command = service.get("command") or []
    return shlex.split(command) if isinstance(command, str) else list(command)


def _flags(command):
    """A listener command as {flag: [values]}; repeated flags keep order."""
    flags = {}
    index = 0
    while index < len(command):
        token = command[index]
        assert token.startswith("--"), "unexpected bare argument %r" % token
        index += 1
        if index < len(command) and not command[index].startswith("--"):
            flags.setdefault(token, []).append(command[index])
            index += 1
        else:
            flags.setdefault(token, []).append("")
    return flags


def _setting(flags, key):
    for item in flags.get("--setting", []):
        name, _, value = item.partition("=")
        if name == key:
            return value
    return None


def _resolver_config():
    """dnsmasq's config as a list of (option, value); comments dropped."""
    options = []
    for line in (LAB / "resolver.conf").read_text().splitlines():
        # Whole-line comments only: `server=/zone/addr#port` has a `#` in
        # it that is not one, so a trailing-comment rule would eat the port.
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        option, _, value = line.partition("=")
        options.append((option.strip(), value.strip()))
    return options


def _instructions(path):
    """A Dockerfile without its comments, which name what they forbid."""
    return "\n".join(line for line in Path(path).read_text().splitlines()
                     if not line.lstrip().startswith("#"))


# The two spellings of the compose command. The standalone one is also the
# start of a filename, so that pattern refuses a `.yml` or `.yaml` after it:
# a reference to `software/c2/docker-compose.yml` is not an invocation.
_COMPOSE_PLUGIN = re.compile(r"\bdocker compose\b")
_COMPOSE_STANDALONE = re.compile(r"\bdocker-compose(?!\.ya?ml)\b")


def _load_entry():
    spec = importlib.util.spec_from_file_location(
        "lab_beacon_entry", LAB / "beacon_entry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = _load(LAB_COMPOSE)
        cls.services = cls.compose["services"]

    def test_the_project_and_its_services_are_the_ones_the_driver_expects(self):
        self.assertEqual(self.compose["name"], "raccoon-lab")
        self.assertEqual(
            set(self.services),
            {"teamserver", "resolver", "listener-dns", "listener-smb",
             "beacon"})
        self.assertEqual(
            set(self.compose["networks"]),
            {"beacon-net", "relay-net", "c2-net"})

    def test_the_lab_publishes_no_udp_port(self):
        # Measured: published UDP does not arrive on macOS. The beacon is a
        # container so the datagram never crosses the host boundary; a
        # published UDP port would mean someone had moved it back.
        published = _published(self.compose)
        self.assertTrue(
            published,
            "nothing is published at all, so this test would pass for a "
            "reader that found no ports; the operator socket is published")
        udp = [entry for entry in published if entry[3].lower() != "tcp"]
        self.assertEqual(udp, [], "a UDP port is published: %r" % (udp,))

    def test_the_operator_socket_is_published_on_tcp_and_on_loopback_only(self):
        operator = [entry for entry in _published(self.compose)
                    if entry[0] == "teamserver"]
        self.assertEqual([entry[2] for entry in operator], [8444])
        self.assertEqual(operator[0][3], "tcp")
        # The shipped file's property, kept: the GUI is not on the network.
        self.assertEqual(operator[0][1], "127.0.0.1")
        self.assertEqual(
            [entry for entry in _published(self.compose)
             if entry[0] != "teamserver"], [],
            "only the operator socket is reachable from the host")

    def test_the_beacon_is_not_on_the_relay_network(self):
        # The listener is the one thing that bridges. A beacon on relay-net
        # could reach the team server and the severance would be a fiction.
        beacon = _networks(self.services["beacon"])
        self.assertNotIn("relay-net", beacon)
        # Exactly these two: beacon-net to reach the resolver, and c2-net
        # so that it registers for real before the driver detaches it.
        self.assertEqual(set(beacon), {"beacon-net", "c2-net"})

    def test_the_beacon_shares_no_network_with_the_listener_but_beacon_net(self):
        beacon = set(_networks(self.services["beacon"]))
        for name in ("listener-dns", "listener-smb"):
            shared = beacon & set(_networks(self.services[name]))
            self.assertEqual(shared, {"beacon-net"}, name)

    def test_the_team_server_is_not_on_the_beacon_network(self):
        # HTTPS cannot route because the address is not on any network the
        # beacon is left holding once it is detached from c2-net.
        self.assertNotIn(
            "beacon-net", _networks(self.services["teamserver"]))
        self.assertEqual(
            set(_networks(self.services["teamserver"])),
            {"c2-net", "relay-net"})

    def test_the_dns_listener_is_on_both_the_beacon_and_relay_networks(self):
        self.assertEqual(
            set(_networks(self.services["listener-dns"])),
            {"beacon-net", "relay-net"})

    def test_the_resolver_is_on_the_beacon_network_and_nothing_else(self):
        self.assertEqual(
            set(_networks(self.services["resolver"])), {"beacon-net"})

    def test_the_beacon_network_declares_a_subnet_holding_both_static_ips(self):
        declared = self.compose["networks"]["beacon-net"]
        subnets = [ipaddress.ip_network(entry["subnet"]) for entry in
                   declared["ipam"]["config"]]
        self.assertEqual(len(subnets), 1)
        for name in ("resolver", "listener-dns"):
            address = ipaddress.ip_address(
                _networks(self.services[name])["beacon-net"]["ipv4_address"])
            self.assertIn(address, subnets[0], name)

    def test_the_networks_that_carry_no_operator_traffic_are_internal(self):
        # Nothing in the lab has any business reaching the internet, and a
        # network that cannot is one less thing that can make a run depend
        # on where it ran.
        for name in ("beacon-net", "relay-net"):
            self.assertTrue(self.compose["networks"][name].get("internal"),
                            name)
        self.assertFalse((self.compose["networks"]["c2-net"] or {})
                         .get("internal"),
                         "a published port needs a network that is not "
                         "internal")

    def test_the_resolver_forwards_the_zone_to_the_listener_by_ip(self):
        # dnsmasq's server=/zone/addr#port takes an IP, not a hostname: it
        # parses its config before it could resolve anything.
        listener = self.services["listener-dns"]
        flags = _flags(_command(listener))
        zone = _setting(flags, "zone")
        port = flags["--bind-port"][0]
        address = _networks(listener)["beacon-net"]["ipv4_address"]

        forwards = [value for option, value in _resolver_config()
                    if option == "server"]
        self.assertEqual(forwards, ["/%s/%s#%s" % (zone, address, port)])
        # And it really is an address, not a name that happens to parse.
        ipaddress.IPv4Address(forwards[0].split("/")[2].split("#")[0])

    def test_the_resolver_logs_what_crossed_it_and_asks_nobody_else(self):
        options = dict(_resolver_config())
        self.assertIn("log-queries", options)
        self.assertTrue(options.get("log-facility", "").startswith("/"),
                        "the driver reads the log from a file path")
        # Hermetic: the only name it can answer is the zone's, so a query
        # that appears in the log was one the beacon really sent.
        self.assertIn("no-resolv", options)
        self.assertIn("no-hosts", options)

    def test_dnsmasq_keeps_its_cache(self):
        # The listener answers with TTL 1 and a cached rescue would be a
        # defect worth catching, so turning the cache off would hide it.
        sizes = [value for option, value in _resolver_config()
                 if option == "cache-size"]
        self.assertEqual([size for size in sizes if int(size) == 0], [],
                         "cache-size=0 turns the cache off")
        self.assertNotIn("no-cache", dict(_resolver_config()))
        # And the config file is the only place the cache can be turned
        # off. The resolver's ENTRYPOINT is dnsmasq itself, so a `command`
        # here would be appended to its argument list, and a dnsmasq
        # command-line option beats the conf-file -- `--cache-size=0` added
        # to this service would silently defeat everything above.
        self.assertFalse(
            self.services["resolver"].get("command"),
            "the mounted conf-file is the resolver's whole effective "
            "configuration; a command would override it unseen")

    def test_the_resolver_config_is_mounted_not_baked_in(self):
        mounts = [str(volume) for volume in
                  self.services["resolver"].get("volumes") or []]
        self.assertTrue(
            any(mount.startswith("./resolver.conf:") and mount.endswith(":ro")
                for mount in mounts), mounts)

    def test_the_beacon_starts_on_c2_net_so_it_can_register_for_real(self):
        self.assertIn("c2-net", _networks(self.services["beacon"]))
        self.assertIn("c2-net", _networks(self.services["teamserver"]))

    def test_the_smb_listener_is_behind_a_profile(self):
        # Scenarios 1 and 2 must not have an SMB listener on beacon-net.
        self.assertEqual(self.services["listener-smb"].get("profiles"),
                         ["smb"])
        self.assertFalse(self.services["listener-dns"].get("profiles"))

    def test_the_labs_documentation_names_both_compose_invocations(self):
        # A documentation guard and nothing more. It reads comments, so it
        # is no evidence that either command runs anywhere -- only that the
        # lab never tells a reader just one of them. Measured here:
        # `docker compose` answers `docker: unknown command` on this
        # machine, which carries only the v1 standalone binary, while newer
        # `ubuntu-latest` images carry only the plugin and have dropped the
        # standalone. So a file naming one form is an instruction that
        # fails for whoever has the other, and tools/e2e_lab.py has to
        # detect which one works rather than assume.
        for path in sorted(LAB.iterdir()):
            if not path.is_file():
                continue
            text = path.read_text()
            plugin = bool(_COMPOSE_PLUGIN.search(text))
            standalone = bool(_COMPOSE_STANDALONE.search(text))
            self.assertEqual(
                plugin, standalone,
                "%s names `docker compose`=%s but `docker-compose`=%s; "
                "neither spelling exists on every machine" % (
                    path.name, plugin, standalone))
        # And not vacuously: the compose file's header is where a reader
        # looks for the command that brings the lab up, so it must say both
        # rather than say nothing.
        self.assertTrue(_COMPOSE_PLUGIN.search(LAB_COMPOSE.read_text()),
                        "the compose header names no way to run the lab")


class ShippedShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = _load(LAB_COMPOSE)["services"]
        cls.shipped = _load(SHIPPED_COMPOSE)["services"]

    def _normalised(self, service, shipped):
        """A listener's flags with the two values a lab must change blanked."""
        flags = _flags(_command(service))
        relay = urlsplit(flags["--relay-url"][0])
        flags["--relay-url"] = [relay.path or "/"]
        if shipped:
            self.assertEqual(relay.hostname, "host.docker.internal")
        flags["--setting"] = [item.split("=", 1)[0]
                              for item in flags.get("--setting", [])]
        return flags

    def test_the_labs_listener_command_matches_the_shipped_compose(self):
        # Risk from the spec: a lab that drifts proves a shape nobody
        # deploys. What may differ is where the relay is (a service name,
        # not host-gateway) and the zone's value; everything else, down to
        # the name and the port, has to be the same.
        for lab_name, shipped_name in (
                ("listener-dns", "raccoon-listener-dns"),
                ("listener-smb", "raccoon-listener-smb")):
            self.assertEqual(
                self._normalised(self.lab[lab_name], False),
                self._normalised(self.shipped[shipped_name], True),
                lab_name)

    def test_the_lab_relays_to_the_team_server_by_service_name(self):
        for name in ("listener-dns", "listener-smb"):
            relay = urlsplit(
                _flags(_command(self.lab[name]))["--relay-url"][0])
            self.assertEqual(relay.hostname, "teamserver", name)
            self.assertEqual(relay.port, 8443, name)

    def test_the_labs_listener_posture_matches_the_shipped_compose(self):
        for lab_name, shipped_name in (
                ("listener-dns", "raccoon-listener-dns"),
                ("listener-smb", "raccoon-listener-smb")):
            for key in ("user", "read_only", "cap_drop", "security_opt"):
                self.assertIn(key, self.shipped[shipped_name], key)
                self.assertEqual(self.lab[lab_name].get(key),
                                 self.shipped[shipped_name][key],
                                 "%s %s" % (lab_name, key))

    def test_the_lab_uses_the_shipped_listener_dockerfile(self):
        for name in ("listener-dns", "listener-smb"):
            build = self.lab[name]["build"]
            context = (LAB / build["context"]).resolve()
            dockerfile = (context / build["dockerfile"]).resolve()
            self.assertEqual(dockerfile, SHIPPED_LISTENER_DOCKERFILE, name)
            self.assertEqual(context, REPO, name)
        # Both services name one image, so it is built once, and the
        # lab has no Dockerfile of its own for a listener to drift into.
        self.assertEqual(self.lab["listener-dns"]["image"],
                         self.lab["listener-smb"]["image"])
        self.assertEqual(
            sorted(path.name for path in LAB.glob("*.Dockerfile")),
            ["beacon.Dockerfile", "resolver.Dockerfile",
             "teamserver.Dockerfile"])

    def test_the_lab_does_not_use_the_shipped_team_server_image(self):
        # That image carries gcc, nmap, a graphical RDP client and a VNC
        # viewer, and its build takes many minutes.
        dockerfile = (LAB / self.lab["teamserver"]["build"]["dockerfile"])
        self.assertEqual(dockerfile.parent, LAB)
        self.assertNotEqual(dockerfile.resolve(),
                            (REPO / "software" / "c2" / "Dockerfile"))


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.services = _load(LAB_COMPOSE)["services"]

    def test_the_source_is_bind_mounted_read_only_not_copied(self):
        for name in ("teamserver", "beacon"):
            mounts = [str(volume) for volume in
                      self.services[name].get("volumes") or []]
            repo_mounts = [mount for mount in mounts
                           if mount.startswith("../../..:")]
            self.assertEqual(len(repo_mounts), 1, "%s: %r" % (name, mounts))
            self.assertTrue(repo_mounts[0].endswith(":ro"), repo_mounts[0])
        for path in ("teamserver", "beacon", "resolver"):
            text = (LAB / ("%s.Dockerfile" % path)).read_text()
            self.assertNotRegex(text, r"(?m)^\s*COPY\s+software",
                                "%s copies project source" % path)

    def test_the_beacon_image_cannot_import_the_server(self):
        # A beacon that can import the server is a beacon that might.
        text = _instructions(LAB / "beacon.Dockerfile").lower()
        for package in ("flask", "cryptography", "werkzeug", "jinja2"):
            self.assertNotIn(package, text)

    def test_the_team_server_image_installs_what_the_server_imports(self):
        text = _instructions(LAB / "teamserver.Dockerfile").lower()
        self.assertIn("flask", text)
        self.assertIn("cryptography", text)
        # Not impacket, netexec, requests or anything the shipped image
        # carries: the server imports without them.
        for package in ("impacket", "netexec", "nmap", "pyyaml"):
            self.assertNotIn(package, text)

    def test_the_images_are_the_four_the_lab_needs(self):
        compose = _load(LAB_COMPOSE)
        built = {name: service["build"]["dockerfile"]
                 for name, service in compose["services"].items()
                 if name not in ("listener-dns", "listener-smb")}
        self.assertEqual(built, {
            "teamserver": "teamserver.Dockerfile",
            "beacon": "beacon.Dockerfile",
            "resolver": "resolver.Dockerfile"})


class BeaconEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = _load_entry()
        cls.services = _load(LAB_COMPOSE)["services"]

    def _config(self, scenario):
        return self.entry.build_config(
            scenario, zone="c2.lab", key="a2V5", resolver="192.0.2.53",
            beacon_port=8443, smb_port=8445, quic_port=8445)["c2"]

    def test_every_scenario_enables_all_four_transports(self):
        # The ladder has to run all the way down for the legs to be
        # attempted, and the zone is what the resolver forwards.
        for scenario in self.entry.SCENARIOS:
            config = self._config(scenario)
            for leg in ("https", "dns", "smb", "quic"):
                self.assertTrue(config[leg]["enabled"], (scenario, leg))
            self.assertEqual(config["dns"]["domain"], "c2.lab")
            self.assertEqual(config["dns"]["resolver"], "192.0.2.53")

    def test_the_scenarios_are_the_three_the_design_names(self):
        self.assertEqual(set(self.entry.SCENARIOS),
                         {"rescue", "stale-token", "smb-up"})

    def test_only_smb_up_points_smb_at_a_listener_on_the_beacon_network(self):
        beacon_net = {name for name, service in self.services.items()
                      if "beacon-net" in _networks(service)}
        for scenario in self.entry.SCENARIOS:
            host = self._config(scenario)["smb"]["server"].rsplit(":", 1)[0]
            self.assertIn(host, self.services, "%s: %s" % (scenario, host))
            if scenario == "smb-up":
                self.assertEqual(host, "listener-smb")
                self.assertIn(host, beacon_net)
            else:
                # An address on c2-net: it routes while the beacon is
                # attached and does not once it is detached.
                self.assertNotIn(host, beacon_net, scenario)
                self.assertIn("c2-net", _networks(self.services[host]))

    def test_the_https_leg_points_at_the_team_server_by_name(self):
        for scenario in self.entry.SCENARIOS:
            url = self._config(scenario)["https"]["callback_url"]
            self.assertEqual(urlsplit(url).hostname, "teamserver")
            self.assertEqual(urlsplit(url).port, 8443)

    def test_the_entrys_ports_agree_with_the_compose_file(self):
        environment = self.services["beacon"]["environment"]
        env = (environment if isinstance(environment, dict) else
               dict(item.split("=", 1) for item in environment))
        command = _command(self.services["teamserver"])
        team = _flags(command[command.index("software.c2.server") + 1:])
        self.assertEqual(env["LAB_BEACON_PORT"], team["--port"][0])
        self.assertEqual(
            env["LAB_SMB_PORT"],
            _flags(_command(self.services["listener-smb"]))["--bind-port"][0])


class DriverTests(unittest.TestCase):
    """`tools/e2e_lab.py`, judged without Docker.

    The driver needs Docker; its tests must not, because they run in the
    normal suite on every machine. So these check the contract a reader
    and a CI job depend on -- the parser, the exit codes, the refusal to
    reuse a stale project -- and leave what Docker actually does to the
    driver's own run.
    """

    @classmethod
    def setUpClass(cls):
        from tools import e2e_lab
        cls.driver = e2e_lab
        cls.source = (REPO / "tools" / "e2e_lab.py").read_text()

    def test_it_exits_2_and_says_so_without_docker(self):
        # tools/listener_docker_rig.py's convention: a missing Docker must
        # never fail in a way that looks like a product fault. 2 is the
        # house code for "I could not run", distinct from 1, "it failed".
        import io
        import unittest.mock

        err = io.StringIO()
        with unittest.mock.patch.object(self.driver.shutil, "which",
                                        lambda _name: None), \
             unittest.mock.patch("sys.stderr", err):
            code = self.driver.main(["rescue"])
        self.assertEqual(code, 2)
        self.assertIn("docker", err.getvalue().lower())

    def test_it_refuses_to_start_when_the_projects_containers_exist(self):
        # Review Focus 4 from the design. A reused container would report a
        # pass that means nothing: the beacon inside it has already run its
        # cycles, and its resolver log already holds a rescue.
        self.assertIn("_existing_containers", self.source)
        names = self.driver._existing_containers.__doc__ or ""
        self.assertTrue(names.strip(), "the refusal needs its reason written")

    def test_the_refusal_is_scoped_to_the_labs_own_project(self):
        # There are other people's containers on a developer's machine --
        # fifteen of them on mine while this was written. A driver that
        # refused on any running container, or tore one down, would be a
        # destructive bug rather than a safety check.
        #
        # The property is that every compose call goes through one helper
        # that injects `-p PROJECT`, and that nothing reaches for `down`
        # outside it. The first version of this test forbade "down" in any
        # `_compose([...])` call, which banned the legitimate teardown and
        # asserted the opposite of what was meant.
        self.assertRegex(self.source, r'command = compose \+ \["-p", PROJECT')
        raw = re.findall(r'subprocess\.run\(\s*\[([^\]]*)\]', self.source)
        for call in raw:
            self.assertNotIn('"down"', call,
                             "a teardown outside the project-scoped helper "
                             "could take another project down with it")

    def test_an_unknown_scenario_is_refused_by_name(self):
        # python 3.9's argparse validates the empty list that nargs="*"
        # produces against `choices` and rejects it, so the names are
        # checked by hand; this pins that the check still happens.
        with self.assertRaises(SystemExit):
            self.driver.main(["no-such-scenario"])

    def test_the_parser_flags_mean_what_the_design_says(self):
        parser = self.driver.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.scenarios, [])
        self.assertFalse(args.keep)
        self.assertFalse(args.shipped_image)
        chosen = parser.parse_args(["rescue", "--keep", "--shipped-image"])
        self.assertEqual(chosen.scenarios, ["rescue"])
        self.assertTrue(chosen.keep)
        self.assertTrue(chosen.shipped_image)

    def test_every_scenario_name_is_reachable_from_the_parser(self):
        parser = self.driver.build_parser()
        for name in self.driver.SCENARIOS:
            self.assertEqual(parser.parse_args([name]).scenarios, [name])

    def test_the_scenarios_it_offers_are_the_ones_the_entry_script_knows(self):
        # The driver chooses a scenario and beacon_entry.py runs it. A name
        # in one and not the other is a run that dies in the container with
        # an argparse error the driver would report as a lab fault.
        self.assertEqual(set(self.driver.SCENARIOS),
                         set(_load_entry().SCENARIOS))

    def test_it_reports_the_architecture_it_ran_on(self):
        # From the design's risk table: aarch64 here, amd64 in CI. A report
        # that does not say which machine produced it cannot be acted on,
        # and this project has twice been bitten by a platform difference
        # nobody recorded.
        self.assertIn("machine", self.source)
        self.assertRegex(self.source, r"os\.uname\(\)|platform\.machine\(\)")

    def test_it_detects_which_compose_command_exists(self):
        # Measured: `docker compose` does not work on this development
        # machine and the standalone `docker-compose` does, while newer
        # ubuntu-latest images ship the plugin and have dropped the
        # standalone. Hardcoding either breaks the other.
        self.assertTrue(_COMPOSE_PLUGIN.search(self.source),
                        "the plugin form is never tried")
        self.assertTrue(_COMPOSE_STANDALONE.search(self.source),
                        "the standalone form is never tried")

    def test_the_teardown_cannot_be_skipped_by_a_failure(self):
        # A scenario that raises must still take its containers down, or
        # the next run refuses to start and the one after reuses state.
        self.assertIn("finally", self.source)
        self.assertRegex(self.source, r'"down"')


class ScenarioTests(unittest.TestCase):
    """The three scenarios, and what each one is for.

    Each exists to make one claim falsifiable, and the claims differ: a
    scenario whose expectations were copied from its neighbour would pass
    for the wrong reason. These check the declarations rather than the
    runs, because a run needs Docker and these do not.
    """

    @classmethod
    def setUpClass(cls):
        from tools import e2e_lab
        cls.driver = e2e_lab
        cls.source = (REPO / "tools" / "e2e_lab.py").read_text()

    def test_stale_token_gives_the_listener_a_token_the_server_rejects(self):
        # Tasking over DNS needs that token; the rescue does not, because
        # it goes through the beacon handler. So the ladder runs all the
        # way down and SMB and QUIC are really attempted -- which is the
        # only way this lab can prove the leg-recording fix on Linux.
        env = self.driver.SCENARIOS["stale-token"].get("env", {})
        self.assertIn("LAB_DNS_LISTENER_TOKEN", env)
        compose = _load(LAB_COMPOSE)["services"]
        server = compose["teamserver"]["environment"]
        listener = compose["listener-dns"]["environment"]
        self.assertTrue(
            any("LAB_SERVER_LISTENER_TOKEN" in entry for entry in server),
            "the server's token must be settable separately or the two "
            "cannot be made to differ")
        self.assertTrue(
            any("LAB_DNS_LISTENER_TOKEN" in entry for entry in listener))
        self.assertNotEqual(env["LAB_DNS_LISTENER_TOKEN"],
                            self.driver.DEFAULT_LISTENER_TOKEN)

    def test_stale_token_expects_the_lower_legs_to_be_attempted(self):
        # The point of the scenario. On Linux a dead QUIC endpoint raises
        # nothing and merely times out, so an unrecorded leg packs as
        # `not_attempted` and the operator is told "not tried" about a leg
        # that was tried. Anything but that word is the fix working.
        expect = self.driver.SCENARIOS["stale-token"]
        self.assertTrue(expect.get("legs_attempted"),
                        "stale-token must require smb and quic to be "
                        "reported as attempted")
        self.assertEqual(set(expect["legs_attempted"]), {"smb", "quic"})

    def test_smb_up_expects_no_rescue_because_an_upstream_leg_delivered(self):
        expect = self.driver.SCENARIOS["smb-up"]
        self.assertEqual(expect.get("rescues"), 0)
        self.assertEqual(expect.get("delivered_by"), "smb")

    def test_smb_up_keeps_the_dns_leg_armed(self):
        # Disabling DNS would make "no rescue was sent" vacuous:
        # _maybe_rescue returns immediately when DNS is off, so the latch
        # would never be armed and the absence would prove nothing. The
        # scenario therefore keeps the stale token: the resolver answers,
        # the latch is armed, and tasking over DNS still returns nothing.
        env = self.driver.SCENARIOS["smb-up"].get("env", {})
        self.assertIn("LAB_DNS_LISTENER_TOKEN", env)
        self.assertNotEqual(env["LAB_DNS_LISTENER_TOKEN"],
                            self.driver.DEFAULT_LISTENER_TOKEN)

    def test_only_smb_up_runs_the_smb_listener(self):
        # Every other scenario needs SMB unreachable, so the listener is
        # behind a profile and only this scenario asks for it.
        self.assertTrue(self.driver.SCENARIOS["smb-up"].get("profile"))
        for name in ("rescue", "stale-token"):
            self.assertFalse(self.driver.SCENARIOS[name].get("profile"),
                             "%s must not start the SMB listener" % name)

    def test_the_rescue_scenario_expects_exactly_one(self):
        self.assertEqual(self.driver.SCENARIOS["rescue"].get("rescues"), 1)

    def test_every_scenario_says_what_it_expects(self):
        # A scenario with no expectation would pass by running.
        for name, spec in self.driver.SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertTrue(
                    "rescues" in spec or "legs_attempted" in spec,
                    "%s asserts nothing about the outcome" % name)


WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


class CiTests(unittest.TestCase):
    """The workflow, which is the only thing that runs any of this on Linux.

    This repository had no CI at all until now, and the whole argument for
    the lab is that two of the four defects it chases could not surface on
    macOS. A workflow that silently skipped the Linux-only paths would
    report green over exactly what it exists to cover, so what it provides
    is asserted here rather than assumed.
    """

    @classmethod
    def setUpClass(cls):
        # Deliberately not a skip. A missing workflow is the failure this
        # class exists to catch: skipping would mean that deleting CI makes
        # its guard disappear with it, which is the same silent-green
        # failure the node check below is about.
        cls.text = WORKFLOW.read_text() if WORKFLOW.exists() else ""
        cls.doc = yaml.safe_load(cls.text) if cls.text else {"jobs": {}}

    def test_the_workflow_exists(self):
        self.assertTrue(WORKFLOW.exists(),
                        "this repository's only Linux coverage is the "
                        "workflow at %s" % WORKFLOW.relative_to(REPO))

    def test_the_workflow_parses_and_has_both_jobs(self):
        # Two jobs, not one: they fail for different reasons and a reader
        # should be able to tell which broke.
        self.assertEqual(set(self.doc["jobs"]), {"tests", "lab"})

    def test_ci_installs_the_three_packages_the_suite_needs(self):
        # Measured: without git, ffmpeg and procps the suite reports 19
        # errors and 6 failures that say nothing about the code -- the
        # requirements-floor and leak-walk tests shell out to git, the
        # figure tools encode with ffmpeg, and the supervisor and tunnel
        # spawn tests read a child's command line with ps.
        for package in ("git", "ffmpeg", "procps"):
            with self.subTest(package=package):
                self.assertIn(package, self.text)

    def test_ci_provides_node(self):
        # The hard input from the notification task: its dedupe and
        # batching tests are @skipUnless(shutil.which("node")), so without
        # node they SKIP SILENTLY and the logic this branch added goes
        # unverified while the job still reports green. That is the exact
        # failure mode the lab exists to prevent.
        self.assertIn("node", self.text.lower())

    def test_ci_pins_the_python_the_suite_is_documented_for(self):
        # software/tests/requirements.txt says the suite runs in a 3.9 venv
        # and has only ever run against it. Testing a version nobody
        # develops against would report failures nobody asked for.
        self.assertIn("3.9", self.text)

    def test_the_tests_job_runs_the_whole_suite_the_documented_way(self):
        body = yaml.dump(self.doc["jobs"]["tests"])
        self.assertIn("unittest discover -s software/tests -t .", body)

    def test_the_lab_job_runs_the_driver(self):
        body = yaml.dump(self.doc["jobs"]["lab"])
        self.assertIn("tools/e2e_lab.py", body)

    def test_ci_passes_no_secret_to_either_job(self):
        # The lab generates its key per run with os.urandom, and nothing
        # here needs a credential. What must be absent is a REFERENCE --
        # `${{ secrets.X }}` is the only way a workflow reads one -- and
        # not the word: the first version of this test forbade the string
        # "secrets." and was failed by the comment in the workflow
        # explaining why there are none. assertNotIn also echoed the whole
        # file into the failure, which is why this reports a count.
        references = re.findall(r"\$\{\{\s*secrets\.", self.text)
        self.assertEqual(references, [],
                         "the workflow reads %d secret(s); the lab needs "
                         "none and a reference is a standing invitation to "
                         "add more" % len(references))

    def test_both_jobs_run_on_linux(self):
        for job in ("tests", "lab"):
            with self.subTest(job=job):
                self.assertIn("ubuntu", self.doc["jobs"][job]["runs-on"])

    def test_the_workflow_says_why_the_packages_are_there(self):
        # Three apt packages with no reason beside them are three packages
        # the next person deletes. Each measured consequence is named.
        self.assertRegex(self.text, r"#.*ffmpeg|ffmpeg.*#")
        self.assertIn("skip", self.text.lower())


if __name__ == "__main__":
    unittest.main()

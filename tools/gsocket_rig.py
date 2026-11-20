#!/usr/bin/env python3
"""An end-to-end run of the gsocket leg, offline or through the real GSRN.

The suite proves the leg's parts. This proves the whole: a real team
server on its two real sockets, a real `SecretStore`, a real
`CarrierSupervisor`, a real `Beacon` with its four other legs switched
off, a real task queued through the real operator route, and the real
result coming back.

Two modes, and the difference between them is exactly one hop:

    python3 tools/gsocket_rig.py
        The carrier's place is taken by a local TCP forward. Nothing
        leaves the machine. This is what CI could run.

    python3 tools/gsocket_rig.py --real /path/to/gs-netcat
        Two real `gs-netcat` processes pair through the Global Socket
        Relay Network. **This sends traffic to third-party
        infrastructure from whatever machine runs it**, which is the one
        thing `docs/LISTENERS.md` says carries OPSEC meaning here, so it
        is never the default and never runs in CI.

Why a rig and not another test: the suite's job is to fail when the code
is wrong, and it does. This exists to be *watched* by somebody deciding
whether to trust the leg on an engagement, which is why every line it
prints names the property it just established rather than a test id.

Three things it has already caught that the suite did not:

  * the server-side carrier dying instantly, because the first stand-in
    written for this rig bound `-p` in the server shape -- the exact
    mistake `software/tests/data/fake_gs_netcat.sh` carries a comment
    about. A row that said `running: false` is what gave it away;
  * `history` staying empty, because the rig queued its task straight
    into `task_queues` instead of through the operator route that writes
    the history entry. The rig was wrong and the product was right, but
    only a run through the real route could say which;
  * `gs-netcat -g` minting **22** characters, not the 21 its own source
    comment claims (`b58[22] = '\\0'` terminates at index 22, so the
    string is indices 0..21). `SECRET_MIN_LEN` is deliberately below
    both -- see `software/c2/gsocket/secrets.py`.
"""

import argparse
import base64
import json
import logging
import os
import pathlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from software.c2 import beacon as beacon_mod                          # noqa: E402
from software.c2 import dns_rescue                                    # noqa: E402
from software.c2 import server as server_mod                          # noqa: E402
from software.c2.beacon import Beacon                                 # noqa: E402
from software.c2.gsocket.carrier import GsocketCarrier                # noqa: E402
from software.c2.gsocket.config import CarrierSpec, validate_leg      # noqa: E402
from software.c2.gsocket.secrets import SecretStore, secretstore_path  # noqa: E402
from software.c2.gsocket.supervisor import CarrierSupervisor          # noqa: E402

SHIPPED_STANDIN = REPO / "software" / "tests" / "data" / "fake_gs_netcat.sh"

_GREEN, _RED, _BOLD, _OFF = "\033[32m", "\033[31m", "\033[1m", "\033[0m"
_failures = []


def check(label, ok, detail=""):
    mark = "%sPASS%s" % (_GREEN, _OFF) if ok else "%sFAIL%s" % (_RED, _OFF)
    print("  %s  %s%s" % (mark, label, ("  — %s" % detail) if detail else ""))
    if not ok:
        _failures.append(label)


def step(title):
    print("\n%s%s%s" % (_BOLD, title, _OFF))


# The implant's half of one paired hop, for the offline mode: bind `-p` on
# loopback and pipe it where the relay would have carried it. Deliberately
# *not* used for the server shape, whose `-p` is a destination port -- see
# the module docstring.
_FORWARD = '''#!/usr/bin/env python3
import os, socket, sys, threading

port = None
args = sys.argv[1:]
for i, v in enumerate(args):
    if v == "-p" and i + 1 < len(args):
        port = int(args[i + 1])
if port is None:
    sys.exit(64)
target = int(os.environ["RIG_TARGET_PORT"])


def pump(src, dst):
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.close()
            except OSError:
                pass


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(16)
while True:
    client, _ = listener.accept()
    upstream = socket.socket()
    upstream.connect(("127.0.0.1", target))
    for a, b in ((client, upstream), (upstream, client)):
        threading.Thread(target=pump, args=(a, b), daemon=True).start()
'''


def free_port():
    import socket as s
    sock = s.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run_cycles(beacon, count=1):
    """Real passes of the shipped `_beacon_loop`; only its two sleeps are stubbed."""
    from unittest import mock
    seen = {"n": 0}

    def sleep(*_args, **_kwargs):
        seen["n"] += 1
        if seen["n"] >= count:
            beacon._running = False

    beacon._running = True
    with mock.patch.object(beacon, "_jittered_sleep", side_effect=sleep), \
            mock.patch.object(beacon, "_backoff_sleep", side_effect=sleep):
        beacon._beacon_loop()


class Operator:
    """The operator socket, which is the only one that may be asked anything."""

    def __init__(self, port, token):
        self.port, self.token = port, token

    def get(self, path, port=None):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (port or self.port, path),
            headers={"Authorization": "Bearer %s" % self.token})
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def post(self, path, payload):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=json.dumps(payload).encode(),
            headers={"Authorization": "Bearer %s" % self.token,
                     "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read() or b"{}")


def listening_address(port):
    """What the given TCP port is bound to, as the OS reports it.

    This is the check that settles the one question `GsocketCarrier.argv`'s
    comment used to leave open, and in `--real` mode it settles it by
    observation rather than by reading upstream's C.
    """
    for argv in (["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"],
                 ["ss", "-ltnH", "sport = :%d" % port]):
        try:
            out = subprocess.run(argv, capture_output=True, text=True,
                                 timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            if str(port) in line and "LISTEN" in line.upper():
                return line.split()[-2] if argv[0] == "ss" else line.split()[-2]
    return ""


def wait_for(predicate, seconds, every=0.5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(every)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--real", metavar="GS_NETCAT",
                        help="path to a real gs-netcat; pairs through the "
                             "GSRN, which sends traffic to third-party "
                             "infrastructure from this machine")
    parser.add_argument("--pair-timeout", type=float, default=90.0,
                        help="seconds to wait for the relay to pair the two "
                             "ends (--real only; default 90)")
    parser.add_argument("--serve", action="store_true",
                        help="after the checks, keep the team server up and "
                             "print its operator URL, so the panel can be "
                             "used or photographed with a live carrier and a "
                             "registered agent behind it")
    args = parser.parse_args(argv)
    real = pathlib.Path(args.real).resolve() if args.real else None

    if real is not None:
        print("%s--real: two gs-netcat processes will dial the Global Socket "
              "Relay Network%s" % (_BOLD, _OFF))
        print("  from this machine. That is third-party infrastructure and it "
              "is never the default.\n")
        if not os.access(str(real), os.X_OK):
            parser.error("%s is not executable" % real)

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.basicConfig(level=logging.CRITICAL)
    root = pathlib.Path(tempfile.mkdtemp(prefix="raccoon-gsocket-rig-"))
    beacons, supervisors, servers = [], [], []
    try:
        from werkzeug.serving import make_server

        # ── 1. the team server ──
        step("1. The team server, on its two real sockets")
        key = os.urandom(32)
        crypto = server_mod.ServerCrypto(key)
        data_dir = root / "data"
        # Bound before the app exists: the carrier's spec needs the agent
        # port and the app needs the carrier supervisor.
        agent_httpd = make_server("127.0.0.1", 0, None, threaded=True)
        op_httpd = make_server("127.0.0.1", 0, None, threaded=True)
        agent_port, op_port = agent_httpd.server_port, op_httpd.server_port
        store = SecretStore(secretstore_path(data_dir))

        # ── 2. the credential path ──
        step("2. The credential path, the way the guide tells an operator to")
        if real is not None:
            minted = subprocess.run([str(real), "-g"], capture_output=True,
                                    text=True, timeout=30).stdout.strip()
            check("gs-netcat -g minted a secret", bool(minted),
                  "%d characters" % len(minted))
            check("it clears the store's floor",
                  len(minted) >= 21, "floor is 21, upstream's own comment "
                                     "claims 21 and its code gives %d"
                                     % len(minted))
        else:
            minted = store.generate()
            check("SecretStore.generate() minted a secret", bool(minted),
                  "%d characters" % len(minted))
        store.register_implant("gs-pi-01", minted)
        server_keyfile = store.secret_file_for("gs-pi-01")
        mode = stat.S_IMODE(os.stat(server_keyfile).st_mode)
        check("the server's key file is 0600", mode == 0o600, oct(mode))

        # The implant's copy is placed by hand, with no trailing newline --
        # which is the whole of the documented procedure, so the rig does it
        # the documented way rather than a convenient way.
        implant_keyfile = root / "gsocket.secret"
        fd = os.open(str(implant_keyfile), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(minted)
        check("the implant's copy is placed by hand, 0600, no newline",
              implant_keyfile.read_text() == minted
              and stat.S_IMODE(os.stat(implant_keyfile).st_mode) == 0o600,
              "nothing in the repository writes this file")
        try:
            store.register_implant("gs-pi-02", minted)
            check("a reused secret is refused", False)
        except ValueError as exc:
            check("a reused secret is refused", True, str(exc)[:58])

        # ── 3. the server-side carrier and the app ──
        step("3. The server-side carrier, supervised")
        if real is not None:
            server_binary = real
        else:
            server_binary = SHIPPED_STANDIN
        spec = CarrierSpec(name="gs-pi-01-carrier", identity="gs-pi-01",
                           enabled=True, beacon_host="127.0.0.1",
                           beacon_port=agent_port,
                           binary_path=str(server_binary), sha256="")
        supervisor = CarrierSupervisor([spec], store)
        supervisors.append(supervisor)
        app = server_mod.create_app(crypto, "operator-token", data_dir,
                                    operator_port=op_port,
                                    carrier_supervisor=supervisor)
        agent_httpd.app = op_httpd.app = app
        for httpd in (agent_httpd, op_httpd):
            servers.append(httpd)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
        operator = Operator(op_port, "operator-token")
        check("agent socket %d, operator socket %d" % (agent_port, op_port),
              True, "one app, two sockets, as a deployment runs it")

        supervisor.start("gs-pi-01-carrier")
        row = [r for r in supervisor.status()
               if r["name"] == "gs-pi-01-carrier"][0]
        check("the carrier is up", row["running"], "pid %s" % row["pid"])
        check("its row reports no socket", row["socket"] is None,
              "where a listener reports bind host and port")
        argv_line = GsocketCarrier(spec, str(server_keyfile)).argv()
        check("the secret is a path and never a value", "-s" not in argv_line,
              " ".join(argv_line[1:]))

        # ── 4. the implant ──
        step("4. The implant, with https, dns, smb and quic all switched off")
        local_port = free_port()
        if real is not None:
            implant_binary = real
            os.environ.pop("RIG_TARGET_PORT", None)
        else:
            implant_binary = root / "standin-forward"
            implant_binary.write_text(_FORWARD)
            implant_binary.chmod(0o755)
            # Not `RACCOON_*`: `carrier._child_environment` strips every
            # variable with that prefix on purpose, because that is where
            # this project keeps the AES key and the operator token. A
            # stand-in configured through one would never receive it, which
            # cost one run of this rig to work out.
            os.environ["RIG_TARGET_PORT"] = str(agent_port)
        leg = {"enabled": True, "secret_file": str(implant_keyfile),
               "binary_path": str(implant_binary), "local_port": local_port,
               "ready_timeout_seconds": int(args.pair_timeout)}
        validate_leg(dict(leg))
        check("the leg block validates", True, "c2.fallback.gsocket")
        check("gsocket is last in the chain",
              beacon_mod._FALLBACK_TRANSPORTS ==
              ("https", "dns", "smb", "quic", "gsocket"))
        beacon = Beacon({"c2": {
            "beacon_interval_seconds": 300, "jitter_percent": 0,
            "encryption_key": base64.b64encode(key).decode(),
            "proxy": {"mode": "none"},
            "https": {"enabled": False}, "dns": {"enabled": False},
            "smb": {"enabled": False}, "quic": {"enabled": False},
            "gsocket": leg,
        }})
        beacons.append(beacon)

        # ── 5. the latch ──
        step("5. Lazy, with a warm latch")
        check("no carrier at beacon start", beacon._gsocket_proc is None,
              "a healthy implant holds no GSRN connection at all")
        run_cycles(beacon, 1)
        first = beacon._gsocket_proc
        check("the first cycle with nothing delivered warms it",
              first is not None,
              "pid %s, after the chain was tried" % (first.pid if first else "-"))

        # ── 6. what the forward binds ──
        step("6. What the implant's forward binds")
        wait_for(lambda: bool(listening_address(local_port)), 20)
        bound = listening_address(local_port)
        if real is not None:
            check("measured: it binds every interface, not loopback",
                  bound.startswith("*:") or bound.startswith("0.0.0.0"),
                  "%s — which is why the implant gets a firewall rule "
                  "(software/setup/gsocket_forward_firewall.sh)" % bound)
        else:
            check("the stand-in keeps to loopback", "127.0.0.1" in bound,
                  "%s — a fixture must not open a port to the network of "
                  "whatever machine runs it" % bound)

        # ── 7. registration ──
        step("7. Registration over the only leg there is")
        if real is not None:
            print("  (waiting for the relay to pair the two ends, up to %ds)"
                  % int(args.pair_timeout))

        def registered():
            run_cycles(beacon, 1)
            return beacon._registered

        got = wait_for(registered, args.pair_timeout if real else 10, every=0.2)
        check("the implant registered through the carrier", got)
        agent = None
        for name, info in server_mod.agents.items():
            if info.get("id") == beacon._implant_id:
                agent = name
        check("it reached the fleet", agent is not None, "as %s" % agent)
        check("and adopted the id the server assigned",
              agent is not None and beacon._agent_id == agent,
              str(beacon._agent_id))
        check("the carrier stayed up rather than being restarted",
              first is not None and beacon._gsocket_proc is first, "same pid")

        # ── 8. a task and its result ──
        step("8. A real task, queued through the real operator route")
        if agent is None:
            check("a task could be queued", False,
                  "no agent to queue against — the leg never registered")
            task_id, result = None, None
        else:
            queued = operator.post("/api/agents/%s/task" % agent,
                                   {"cmd": "shell",
                                    "args": "echo gsocket-works"})
            task_id = (queued.get("task") or queued).get("id") \
                or queued.get("task_id")
            check("the operator route accepted it", bool(task_id),
                  str(task_id))

            def answered():
                run_cycles(beacon, 1)
                return server_mod.results.get(task_id) is not None

            wait_for(answered, 60 if real else 10, every=0.2)
            result = server_mod.results.get(task_id)
            check("the result came back", result is not None)
        if result:
            check("its status is ok", result["status"] == "ok",
                  repr(result["output"].strip()[:40]))
            check("the output is the command's own",
                  "gsocket-works" in result["output"])
            check("the agent's own history carries it",
                  any(h.get("task_id") == task_id and h.get("status") == "ok"
                      for h in server_mod.history.get(agent, [])),
                  "filed under %s, not under the implant id" % agent)

        # ── 9. the socket policy and the panel's data ──
        step("9. The socket policy, holding a valid operator token")
        status, body = operator.get("/api/server/listeners", port=agent_port)
        check("the agent socket answers it with the cover reply",
              "listeners" not in body, body.strip()[:46])
        status, body = operator.get("/api/server/listeners")
        check("the operator socket serves it", status == 200, "HTTP %s" % status)
        rows = json.loads(body).get("listeners", []) if status == 200 else []
        carrier_rows = [r for r in rows if r.get("transport") == "gsocket"]
        check("the carrier is in the panel's own data",
              len(carrier_rows) == 1, "%d row(s)" % len(rows))
        if carrier_rows:
            check("still running, still reporting no socket",
                  carrier_rows[0].get("running")
                  and carrier_rows[0].get("socket") is None,
                  "identity %s" % carrier_rows[0].get("identity"))

        # ── 10. the diagnosis, and the field's records ──
        step("10. What a stuck implant says, and what the field's records say")
        stuck = Beacon({"c2": {
            "beacon_interval_seconds": 300, "jitter_percent": 0,
            "encryption_key": base64.b64encode(key).decode(),
            "proxy": {"mode": "none"},
            "https": {"enabled": False}, "dns": {"enabled": False},
            "smb": {"enabled": False}, "quic": {"enabled": False},
            "gsocket": dict(leg, binary_path=str(root / "not-here"),
                            local_port=free_port()),
        }})
        beacons.append(stuck)
        run_cycles(stuck, 2)
        names = {value: key for key, value in dns_rescue.CLASSES.items()}
        klass = stuck._leg_status.get("gsocket", (None, None))[0]
        check("a missing binary reports binary_missing",
              names.get(klass) == "binary_missing", names.get(klass))
        words = server_mod._RESCUE_LEG_WORDS.get("binary_missing")
        check("the server renders that in words", bool(words), repr(words))
        v1 = struct.pack("!BHBHBHBHBHB", 1, 0xBEEF,
                         dns_rescue.CLASSES["timed_out"], 0,
                         dns_rescue.CLASSES["answered"], 0, 0, 0, 0, 0,
                         dns_rescue.FLAG_DNS_ANSWERED)
        old = dns_rescue.unpack(v1)
        check("a 16-byte record from the field still reads",
              old["version"] == 1 and
              names.get(old["gsocket"][0]) == "not_attempted",
              "gsocket reads as not tried, rather than as a lie")

        # ── 11. the generator ──
        step("11. A generated single-file build refuses the leg")
        try:
            server_mod._beacon_gen_config({}, {"gsocket": {"enabled": True}},
                                          "http://x/api/v1/beacon", data_dir)
            check("beacon-gen refuses an enabled gsocket leg", False)
        except ValueError as exc:
            check("beacon-gen refuses an enabled gsocket leg", True,
                  str(exc)[:66])

        if args.serve:
            print("\n%sServing. The panel has a live carrier and a registered "
                  "agent behind it.%s" % (_BOLD, _OFF))
            print("  operator interface : http://127.0.0.1:%d/" % op_port)
            print("  operator token     : operator-token")
            print("  agent socket       : 127.0.0.1:%d  (cover replies only)"
                  % agent_port)
            print("  the carrier's row  : the 📡 button in the header")
            print("\n  Ctrl-C to stop. Everything is torn down on the way out.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                print("\n  stopping")

    finally:
        for one in beacons:
            one._running = False
            try:
                one._gsocket_stop()
            except Exception:
                pass
        for one in supervisors:
            try:
                one.stop_all()
            except Exception:
                pass
        for one in servers:
            one.shutdown()
        shutil.rmtree(root, ignore_errors=True)

    print("\n" + "─" * 68)
    if _failures:
        print("%s%d check(s) failed:%s %s"
              % (_RED, len(_failures), _OFF, "; ".join(_failures)))
        return 1
    if real is not None:
        print("%sEvery check passed, through the real relay network.%s"
              % (_GREEN, _OFF))
    else:
        print("%sEvery check passed.%s One hop was stood in for: the GSRN "
              "pairing itself.\nRun with --real to close that one too."
              % (_GREEN, _OFF))
    return 0


if __name__ == "__main__":
    sys.exit(main())

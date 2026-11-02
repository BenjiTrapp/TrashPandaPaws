/* Agent layer for the operator GUI.
 *
 * Everything the agent adds to the page lives here, not in server.py: the
 * "Automated Attack" button, the stream above the terminal, the drawer on the
 * right. If this file is missing, fails to parse or throws, the operator
 * loses that button and nothing else. That is the property the rest of the
 * file is arranged around:
 *
 *   - the button is inserted by agentInit(), never written into the HTML;
 *   - every request to /api/ai/* goes through aiCall(), which cannot throw;
 *   - every entry point (timer, observer, click) is wrapped so an exception
 *     here cannot reach the page's own setInterval loops;
 *   - /api/ai/status is read on load and on click, never on a timer, so a
 *     service that was never started is asked once, not every few seconds.
 *
 * Reused from the main GUI, not reimplemented: TOKEN's Authorization header
 * (H), toast(), openPanel(), esc(), selectedAgent. They are read at call
 * time; this file is deferred, so the inline script has already defined them.
 *
 * Plain ES2017: no optional chaining, no object spread, no Array#flat.
 */
(function(){
"use strict";

// ── Constants ──

const POLL_MS = {stream: 1500, drawer: 2000, approvals: 1500};
// A failing poll waits twice as long each time, up to this. With the base
// intervals above that is 3s, 6s, 12s, 24s, 30s, 30s... per poll.
const BACKOFF_MAX_MS = 30000;
// Consecutive failures of one poll after which all three stop and the drawer
// offers a retry. Eight is a little over two minutes of trying: long enough
// to ride out a service restart, short enough not to knock on a dead door
// for the rest of the day.
const GIVE_UP_AFTER = 8;
// Failures of one poll before the operator is told (a toast, a banner). One
// or two are noise; three in a row is an outage worth a sentence.
const SAY_AFTER = 3;
const TERMINAL = ["completed", "failed", "aborted"];
// The campaign's own end is shown for a moment, then the regions go, as the
// spec has it: without a running campaign the GUI is the old GUI.
const GRACE_MS = 12000;
const MAX_LINES = 500;
const DEFAULT_MAX_PHASE = 5;

// ── State ──

const A = {
  avail: "unknown",      // "unknown" | "ok" | "down" — the button's three states
  reason: "",            // why "down", as the service or the proxy put it
  status: null,          // last /status body
  rid: null,             // run id being watched
  gen: 0,                // bumped on every attach/teardown; stale timers check it
  camp: null,            // last /campaign/<rid> body
  campWarnings: [],      // opsec warnings of the watched campaign, from /status
  events: [],
  since: 0,
  approvals: [],
  answering: {},         // approval id -> POST in flight
  toasted: {},           // approval id -> already announced
  mode: "agent",         // "agent" | "all"
  opLines: [],
  timers: {},
  fails: {},             // poll name -> consecutive failures
  said: false,           // the outage was announced
  lost: false,           // polling gave up
  note: "",              // why a campaign is no longer followed
  ended: false,
  graceTimer: null,
  collapsed: false,
  paneH: null,
  pausePending: false,
  rendered: {sig: "", mode: "", count: 0},
  knockSig: "",
};

// ── Small helpers ──

function report(e){
  // The console only: the point of the guards is that nothing else sees this.
  try { console.warn("agent.js:", e && e.message ? e.message : e); } catch(_) {}
}

// Wrap an entry point so neither a throw nor a rejected promise escapes it.
function guard(fn){
  return function(){
    try {
      const r = fn.apply(this, arguments);
      if(r && typeof r.catch === "function") r.catch(report);
      return r;
    } catch(e){ report(e); }
  };
}

function escHtml(s){
  if(typeof esc === "function") return esc(s);
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Build DOM with textContent only. Stream text includes tool output the agent
// scanned, i.e. text from the target network; it must never reach innerHTML.
function h(tag, props){
  const el = document.createElement(tag);
  const p = props || {};
  Object.keys(p).forEach(function(k){
    const v = p[k];
    if(v == null || v === false) return;
    if(k === "class") el.className = v;
    else if(k === "text") el.textContent = v;
    else if(k.slice(0, 2) === "on") el.addEventListener(k.slice(2), guard(v));
    else el.setAttribute(k, v === true ? "" : v);
  });
  for(let i = 2; i < arguments.length; i++) addKids(el, arguments[i]);
  return el;
}

function addKids(el, kid){
  if(kid == null || kid === false) return;
  if(Array.isArray(kid)){ kid.forEach(function(k){ addKids(el, k); }); return; }
  el.appendChild(typeof kid === "object" ? kid : document.createTextNode(String(kid)));
}

function notify(type, title, msg, ms){
  try {
    if(typeof toast === "function") toast(type, escHtml(title), escHtml(msg), ms);
  } catch(e){ report(e); }
}

function currentAgent(){
  try { return typeof selectedAgent !== "undefined" ? selectedAgent : null; }
  catch(e){ return null; }
}

function fmtTs(iso){
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "" : d.toTimeString().slice(0, 8);
}

// The stream stamps microseconds, the C2's history whole seconds. Browsers
// disagree about digits beyond milliseconds, so cut to three.
function toMs(iso){
  const t = Date.parse(String(iso || "").replace(/(\.\d{3})\d+/, "$1"));
  return isNaN(t) ? 0 : t;
}

function fmtNum(n, digits, signed){
  const v = Number(n);
  if(!isFinite(v)) return "n/a";
  const s = v.toFixed(digits);
  return signed && v > 0 ? "+" + s : s;
}

function fmtTokens(n){
  const v = Number(n) || 0;
  return v >= 10000 ? Math.round(v / 1000) + "k" : v >= 1000 ? (v / 1000).toFixed(1) + "k" : String(v);
}

function fmtDuration(sec){
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  if(s < 60) return s + "s";
  if(s < 3600) return Math.floor(s / 60) + "m";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

function isTerminal(status){ return TERMINAL.indexOf(status) >= 0; }

// ── The one door to /api/ai ──
//
// Never throws, never rejects: a service that is down, a proxy that answers
// 503, a body that is not JSON all come back as a result with ok=false. This
// is the only place that names the endpoint, so it is the only place that has
// to be guarded. It does not use the page's api(): that discards the HTTP
// status, and the callers need 404 ("the service forgot this campaign",
// final) told apart from 503 ("not there right now", worth retrying).

async function aiCall(path, opts){
  try {
    const r = await fetch("/api/ai/" + path, Object.assign({headers: H}, opts || {}));
    let data = null;
    try { data = await r.json(); } catch(e){ data = null; }
    return {ok: r.ok, status: r.status, data: data};
  } catch(e){
    return {ok: false, status: 0, data: null};
  }
}

function reasonOf(r){
  const d = r.data && typeof r.data === "object" ? r.data : {};
  if(r.status === 0) return "the C2 server could not be reached";
  if(r.status === 503) return d.detail ? "agent service unavailable (" + d.detail + ")"
                                       : (d.error || "agent service unavailable");
  if(r.ok && d.available === false) return d.reason || "the agent is not available";
  if(r.status === 401 || r.status === 403) return "the agent service refused the request" + (d.error ? " (" + d.error + ")" : "");
  return d.error || "unexpected answer (HTTP " + r.status + ")";
}

// ── Status: on load and on click, never on a timer ──

async function agentLoadStatus(){
  const r = await aiCall("status");
  const d = r.ok && r.data && typeof r.data === "object" ? r.data : null;
  A.status = d;
  if(d && d.available === true){ A.avail = "ok"; A.reason = ""; }
  else { A.avail = "down"; A.reason = reasonOf(r); }
  renderButtons();
  if(d) attachFromStatus();
  return r;
}

function allWarnings(){
  const w = A.status && A.status.opsec_warnings;
  const out = [];
  if(w && typeof w === "object") Object.keys(w).forEach(function(profile){
    (Array.isArray(w[profile]) ? w[profile] : []).forEach(function(text){
      out.push({profile: profile, text: String(text)});
    });
  });
  return out;
}

// ── The button ──

function ensureButton(){
  const tb = document.querySelector("#content .toolbar");
  if(!tb) return;
  if(!tb.querySelector(".ai-btn")){
    tb.appendChild(h("button", {class: "ai-btn", type: "button", onclick: agentOnButton}));
  }
  renderButtons();
}

function renderButtons(){
  const btns = document.querySelectorAll(".ai-btn");
  for(let i = 0; i < btns.length; i++) renderButton(btns[i]);
}

function renderButton(b){
  const warns = A.avail === "ok" ? allWarnings().length : 0;
  let title;
  if(A.avail === "ok"){
    const s = A.status || {};
    title = "Automated Attack - " + (s.provider || "?") + " / " + (s.model || "?")
      + " (capability tier " + (s.tier || "?") + ")"
      + (warns ? ". " + warns + " OpSec warning(s); click for details." : "");
  } else if(A.avail === "down"){
    title = "Automated Attack is unavailable: " + A.reason + ". Click to check again.";
  } else {
    title = "Checking the agent service...";
  }
  b.className = "ai-btn" + (A.avail === "ok" ? "" : " disabled")
    + (A.avail === "ok" && A.rid != null && !A.ended ? " live" : "");
  b.setAttribute("title", title);
  b.setAttribute("aria-disabled", A.avail === "ok" ? "false" : "true");
  b.textContent = "";
  b.appendChild(h("span", {class: "ai-dot"}));
  b.appendChild(document.createTextNode("Automated Attack"));
  if(warns) b.appendChild(h("span", {class: "ai-warn-n", text: "\u26A0 " + warns}));
}

async function agentOnButton(){
  await agentLoadStatus();
  if(A.lost) resumePolling();
  agentOpenPanel();
}

// ── Status panel (inside the existing side panel) ──

function openInPanel(title, build){
  // openPanel() writes into #side-panel, which only exists while an agent is
  // open; and it takes an HTML string, so hand it an empty shell and fill that.
  if(typeof openPanel !== "function" || !document.getElementById("side-panel")) return false;
  openPanel(title, '<div class="ai-detail" id="ai-detail"></div>');
  const root = document.getElementById("ai-detail");
  if(!root) return false;
  build(root);
  return true;
}

function kv(rows){
  const dl = h("dl");
  rows.forEach(function(r){
    dl.appendChild(h("dt", {text: r[0]}));
    dl.appendChild(h("dd", {text: r[1]}));
  });
  return dl;
}

function agentOpenPanel(){
  const shown = openInPanel("Automated Attack", function(root){
    const s = A.status || {};
    root.appendChild(h("h4", {text: "Service"}));
    if(A.avail === "ok"){
      root.appendChild(kv([
        ["state", "available"],
        ["model", (s.provider || "?") + " / " + (s.model || "?")],
        ["capability tier", (s.tier || "?") + (s.max_phase ? " (up to phase " + s.max_phase + ")" : "")],
        ["database", s.db_ready === false ? "not ready" : "ready"],
      ]));
    } else {
      root.appendChild(h("pre", {text: "Unavailable: " + A.reason}));
      root.appendChild(h("div", {class: "ai-note", text: "Start the agent service and click the button again."}));
    }
    const warns = allWarnings();
    root.appendChild(h("h4", {text: "OpSec warnings"}));
    if(warns.length){
      root.appendChild(h("div", {class: "ai-warns"},
        h("ul", {}, warns.map(function(w){ return h("li", {text: w.profile + ": " + w.text}); }))));
    } else {
      root.appendChild(h("div", {class: "ai-note", text: "None for the current configuration."}));
    }
    const camps = s.campaigns || [];
    root.appendChild(h("h4", {text: "Campaigns"}));
    if(!camps.length) root.appendChild(h("div", {class: "ai-note", text: "None running."}));
    camps.forEach(function(c){
      root.appendChild(h("div", {},
        "#" + c.run_id + " " + (c.status || "?") + ", phase " + (c.phase == null ? "-" : c.phase)
          + ", score " + (c.score == null ? "-" : c.score) + " ",
        A.rid === c.run_id && !A.ended ? h("span", {class: "ai-note", text: "(shown)"})
          : h("button", {class: "ai-btn-inline", type: "button", text: "Show",
              onclick: function(){ startWatching(c.run_id); }})));
    });
  });
  // No agent open means no side panel; say it where the operator is looking.
  if(!shown){
    if(A.avail === "ok") notify("info", "Automated Attack", "The agent service is available.", 4000);
    else notify("warning", "Automated Attack unavailable", A.reason, 7000);
  }
}

// ── Attaching to a campaign ──

function attachFromStatus(){
  const camps = A.status && Array.isArray(A.status.campaigns) ? A.status.campaigns : [];
  if(A.rid != null && !A.ended){
    const mine = camps.filter(function(c){ return c.run_id === A.rid; })[0];
    if(mine) A.campWarnings = Array.isArray(mine.opsec_warnings) ? mine.opsec_warnings : [];
    return;
  }
  const pick = camps.filter(function(c){ return c.status === "running"; })[0] || camps[0];
  if(pick) startWatching(pick.run_id);
}

function startWatching(rid){
  stopTimers();
  clearTimeout(A.graceTimer);
  A.gen++;
  A.rid = rid;
  A.camp = null; A.events = []; A.since = 0; A.approvals = []; A.answering = {};
  A.opLines = []; A.fails = {}; A.said = false; A.lost = false; A.note = "";
  A.ended = false; A.pausePending = false; A.rendered = {sig: "", mode: "", count: 0}; A.knockSig = "";
  const camps = A.status && Array.isArray(A.status.campaigns) ? A.status.campaigns : [];
  const mine = camps.filter(function(c){ return c.run_id === rid; })[0];
  A.campWarnings = mine && Array.isArray(mine.opsec_warnings) ? mine.opsec_warnings : [];
  mountAll();
  renderButtons();
  Object.keys(POLL_MS).forEach(function(name){ schedule(name, 0); });
}

function teardown(){
  stopTimers();
  clearTimeout(A.graceTimer);
  A.gen++;
  A.rid = null; A.ended = false;
  const gone = document.querySelectorAll(".ai-pane, .ai-grip, .ai-drawer");
  for(let i = 0; i < gone.length; i++) gone[i].remove();
  renderButtons();
}

// ── Polling ──
//
// One setTimeout per poll, re-armed after each answer, instead of a
// setInterval: the next delay depends on how the last request went.

const POLLS = {stream: pollStream, drawer: pollDrawer, approvals: pollApprovals};

function stopTimers(){
  Object.keys(A.timers).forEach(function(k){ clearTimeout(A.timers[k]); });
  A.timers = {};
}

function schedule(name, ms){
  clearTimeout(A.timers[name]);
  const gen = A.gen;
  A.timers[name] = setTimeout(function(){ tick(name, gen); }, ms);
}

async function tick(name, gen){
  try {
    if(gen !== A.gen || A.ended || A.lost) return;
    let r;
    try { r = await POLLS[name](); } catch(e){ report(e); r = {ok: false, status: 0}; }
    if(gen !== A.gen || A.ended) return;
    settle(name, r);
  } catch(e){ report(e); }
}

function settle(name, r){
  // The service answers but has never heard of the run: it was restarted (it
  // marks unfinished runs aborted on the way up) or the run was pruned. That
  // does not get better by asking again.
  if(r.status === 404){
    stopTimers();
    A.ended = true;
    A.note = "The agent service no longer knows this campaign (it may have restarted).";
    notify("warning", "Campaign lost", A.note, 8000);
    renderAll();
    A.graceTimer = setTimeout(guard(teardown), GRACE_MS);
    return;
  }
  if(r.ok){
    A.fails[name] = 0;
    if(A.said && !Object.keys(A.fails).some(function(k){ return A.fails[k] > 0; })){
      A.said = false;
      notify("success", "Agent service back", "Campaign updates resumed.", 4000);
      renderLost();
    }
    if(!A.ended) schedule(name, POLL_MS[name]);
    return;
  }
  // A failure. Each poll backs off on its own, so a dead service costs a few
  // requests a minute, not forty; after GIVE_UP_AFTER in a row for any one of
  // them all three stop and the operator decides.
  A.fails[name] = (A.fails[name] || 0) + 1;
  const n = A.fails[name];
  if(n >= GIVE_UP_AFTER){
    stopTimers();
    A.lost = true;
    A.said = true;
    notify("error", "Agent service not answering", "Stopped polling the campaign. Use Retry in the drawer.", 9000);
    renderLost();
    return;
  }
  if(n >= SAY_AFTER && !A.said){
    A.said = true;
    notify("warning", "Agent service not answering", "Retrying with growing pauses; the campaign itself may still be running.", 6000);
  }
  renderLost();
  schedule(name, Math.min(POLL_MS[name] * Math.pow(2, n), BACKOFF_MAX_MS));
}

function resumePolling(){
  if(A.rid == null) return;
  A.fails = {}; A.said = false; A.lost = false;
  A.gen++;
  renderLost();
  Object.keys(POLL_MS).forEach(function(name){ schedule(name, 0); });
}

async function pollStream(){
  const r = await aiCall("campaign/" + A.rid + "/stream?since=" + A.since);
  const d = r.data;
  if(r.ok && !(d && Array.isArray(d.events))) r.ok = false;
  if(!r.ok) return r;
  if(d.events.length){
    A.events = A.events.concat(d.events);
    A.since = typeof d.next === "number" ? d.next : A.since;
    announce(d.events);
  }
  // The operator's side of "All" is the C2's own history, not the agent's.
  if(A.mode === "all") await loadOpLines();
  agentRenderStream(A.events);
  return r;
}

async function pollDrawer(){
  const r = await aiCall("campaign/" + A.rid);
  if(r.ok && !(r.data && typeof r.data === "object" && "status" in r.data)) r.ok = false;
  if(!r.ok) return r;
  A.camp = r.data;
  agentRenderDrawer(A.camp);
  if(isTerminal(A.camp.status)) finish().catch(report);
  return r;
}

async function pollApprovals(){
  const r = await aiCall("campaign/" + A.rid + "/approvals");
  if(r.ok && !(r.data && Array.isArray(r.data.approvals))) r.ok = false;
  if(!r.ok) return r;
  A.approvals = r.data.approvals;
  A.approvals.forEach(function(ap){
    if(A.toasted[ap.id]) return;
    A.toasted[ap.id] = true;
    notify("warning", "Agent asks for approval", String(ap.action || "an action") + " is waiting in the drawer.", 8000);
  });
  renderKnocks();
  return r;
}

async function finish(){
  const gen = A.gen;
  if(A.ended) return;
  A.ended = true;
  stopTimers();
  // One last look so the closing events and the final state are not the ones
  // missed between two polls. Best effort: the outcome is already known.
  await pollStream();
  if(gen !== A.gen) return;
  A.approvals = [];
  const c = A.camp || {};
  notify(c.status === "completed" ? "success" : "warning",
    "Campaign " + c.status, "#" + A.rid + ": score " + c.score + ", " + c.detections + " detection(s).", 10000);
  renderAll();
  A.graceTimer = setTimeout(guard(teardown), GRACE_MS);
}

function announce(events){
  // The notification area is for what the operator should not miss, not for
  // every dispatch; and a burst of events must not become a burst of toasts.
  let shown = 0;
  events.forEach(function(e){
    if(shown >= 3) return;
    const type = e.kind === "detection" ? "warning" : e.kind === "error" ? "error"
      : e.kind === "phase" ? "info" : null;
    if(!type) return;
    shown++;
    notify(type, "Agent " + e.kind, e.text, 6000);
  });
}

// ── Operator side of the merged view ──

async function loadOpLines(){
  const id = currentAgent();
  if(!id){ A.opLines = []; return; }
  try {
    const hist = await api("/api/agents/" + encodeURIComponent(id) + "/history");
    // Both lanes land in the C2's history; the agent's commands are already
    // in its own stream, so only the operator's are taken from here. Entries
    // without a lane predate lanes and are the operator's.
    const from = A.events.length ? toMs(A.events[0].ts) - 2000 : Date.now();
    A.opLines = (Array.isArray(hist) ? hist : [])
      .filter(function(x){ return x && x.lane !== "agent" && toMs(x.timestamp) >= from; })
      .map(function(x){ return {who: "op", t: toMs(x.timestamp), ts: x.timestamp, h: x}; });
  } catch(e){ report(e); }
}

// ── Mounting: the regions have to survive the page re-rendering #content ──

function mountAll(){
  if(A.rid == null) return;
  mountDrawer();
  mountPane();
  ensureButton();
  renderAll();
}

function mountDrawer(){
  const main = document.querySelector(".main");
  if(!main || main.querySelector(".ai-drawer")) return;
  main.appendChild(h("aside", {class: "ai-drawer"},
    h("h3", {class: "ai-d-title"}),
    h("div", {class: "ai-d-gauge ai-gauge"}, h("i")),
    h("dl", {class: "ai-rows"}),
    h("div", {class: "ai-d-warns"}),
    h("div", {class: "ai-d-knocks"}),
    h("div", {class: "ai-d-lost"})));
}

function mountPane(){
  const host = document.querySelector("#content .terminal-wrap") || document.getElementById("content");
  if(!host || host.querySelector(".ai-pane")) return;
  const toggle = h("span", {class: "ai-toggle"},
    h("button", {type: "button", "data-mode": "agent", text: "Agent", onclick: function(){ setMode("agent"); }}),
    h("button", {type: "button", "data-mode": "all", text: "All", onclick: function(){ setMode("all"); }}));
  const pane = h("div", {class: "ai-pane" + (A.collapsed ? " ai-pane-collapsed" : "")},
    h("div", {class: "ai-pane-head"},
      h("span", {class: "ai-title"}),
      toggle,
      h("button", {type: "button", class: "ai-pause", title: "Pause the campaign", text: "\u23F8", onclick: onPause}),
      h("button", {type: "button", title: "Stop the campaign", text: "\u23F9", onclick: onStop}),
      h("button", {type: "button", class: "ai-fold", title: "Collapse or expand", onclick: onFold})),
    h("div", {class: "ai-pane-body"}));
  if(A.paneH) pane.style.setProperty("--ai-pane-h", A.paneH + "px");
  const grip = h("div", {class: "ai-grip", title: "Drag to resize"});
  grip.addEventListener("mousedown", guard(function(e){ dragGrip(e, pane, grip); }));
  const toolbar = host.querySelector(".toolbar");
  if(toolbar && toolbar.parentNode === host){
    host.insertBefore(pane, toolbar.nextSibling);
    host.insertBefore(grip, pane.nextSibling);
  } else {
    host.insertBefore(grip, host.firstChild);
    host.insertBefore(pane, grip);
  }
  A.rendered = {sig: "", mode: "", count: 0};
}

function dragGrip(e, pane, grip){
  const startY = e.clientY, startH = pane.offsetHeight;
  grip.classList.add("active");
  document.body.style.cursor = "row-resize";
  document.body.style.userSelect = "none";
  const onMove = guard(function(ev){
    A.paneH = Math.max(60, Math.min(startH + ev.clientY - startY, Math.round(window.innerHeight * 0.6)));
    pane.style.setProperty("--ai-pane-h", A.paneH + "px");
  });
  const onUp = guard(function(){
    grip.classList.remove("active");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
  });
  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup", onUp);
}

function onFold(){
  A.collapsed = !A.collapsed;
  const pane = document.querySelector(".ai-pane");
  if(pane) pane.classList.toggle("ai-pane-collapsed", A.collapsed);
  renderPaneHead();
}

function setMode(mode){
  A.mode = mode;
  A.rendered = {sig: "", mode: "", count: 0};
  if(mode === "all") loadOpLines().then(function(){ agentRenderStream(A.events); }).catch(report);
  else agentRenderStream(A.events);
  renderPaneHead();
}

function watchContent(){
  const c = document.getElementById("content");
  if(!c || typeof MutationObserver === "undefined") return;
  // The page replaces #content wholesale whenever an agent is picked, which
  // takes the toolbar and anything mounted in it along. childList only: the
  // inserts this file makes below #content do not wake it again.
  new MutationObserver(guard(function(){ ensureButton(); mountAll(); })).observe(c, {childList: true});
}

// ── Rendering: stream ──

function renderAll(){
  renderPaneHead();
  agentRenderDrawer(A.camp);
  agentRenderStream(A.events);
  renderKnocks();
  renderLost();
}

function renderPaneHead(){
  const pane = document.querySelector(".ai-pane");
  if(!pane) return;
  const c = A.camp || {};
  const max = (A.status && A.status.max_phase) || DEFAULT_MAX_PHASE;
  const state = A.ended ? (c.status || "ended") : (c.status || "starting");
  pane.querySelector(".ai-title").textContent = "\u25C6 Agent \u00B7 run " + A.rid
    + (c.phase != null ? " \u00B7 phase " + c.phase + "/" + max : "") + " \u00B7 " + state;
  const btns = pane.querySelectorAll(".ai-toggle button");
  for(let i = 0; i < btns.length; i++) btns[i].classList.toggle("on", btns[i].getAttribute("data-mode") === A.mode);
  const paused = c.status === "paused";
  const pause = pane.querySelector(".ai-pause");
  pause.textContent = paused ? "\u25B6" : "\u23F8";
  pause.title = paused ? "Resume the campaign" : "Pause the campaign";
  pause.disabled = A.ended || A.pausePending && !paused;
  pane.querySelector(".ai-fold").textContent = A.collapsed ? "\u25BE" : "\u25B4";
}

function mergedItems(events){
  const items = events.map(function(e){ return {who: "ai", t: toMs(e.ts), ts: e.ts, e: e}; });
  if(A.mode !== "all") return items;
  // Stable on ties, so an agent line and an operator line in the same second
  // keep the order they arrived in.
  return items.concat(A.opLines).map(function(x, i){ return {x: x, i: i}; })
    .sort(function(a, b){ return a.x.t - b.x.t || a.i - b.i; })
    .map(function(p){ return p.x; });
}

function lineFor(item){
  const isOp = item.who === "op";
  const text = isOp ? "$ " + item.h.cmd + (item.h.args ? " " + item.h.args : "") : "\u203A " + item.e.text;
  return h("div", {class: "ai-line " + (isOp ? "op" : "k-" + (item.e.kind || "info")),
                   onclick: function(){ openItemDetail(item); }},
    h("span", {class: "ai-ts", text: fmtTs(item.ts)}),
    A.mode === "all" ? h("span", {class: "ai-badge" + (isOp ? " op" : ""), text: isOp ? "OP" : "AI"}) : null,
    h("span", {class: "ai-text", text: text}));
}

function agentRenderStream(events){
  const body = document.querySelector(".ai-pane-body");
  if(!body) return;
  const list = events || [];
  const sig = A.mode + ":" + list.length + ":" + A.opLines.length;
  if(sig === A.rendered.sig) return;
  const stick = body.scrollHeight - body.scrollTop - body.clientHeight < 30;
  const items = mergedItems(list);
  const prev = A.rendered;
  // In the agent view lines only ever arrive at the end, so they are appended
  // and the ones already on screen are left alone: a click is not lost to a
  // redraw. The merged view can interleave, so it redraws when it changed.
  if(A.mode === "agent" && prev.mode === "agent" && prev.count > 0 && prev.count <= items.length){
    items.slice(prev.count).forEach(function(it){ body.appendChild(lineFor(it)); });
    while(body.children.length > MAX_LINES) body.removeChild(body.firstChild);
  } else {
    body.textContent = "";
    if(!items.length){
      body.appendChild(h("div", {class: "ai-empty", text: A.mode === "all" && !currentAgent()
        ? "Open an agent to see its operator commands here."
        : "Waiting for the first event..."}));
    }
    items.slice(-MAX_LINES).forEach(function(it){ body.appendChild(lineFor(it)); });
  }
  A.rendered = {sig: sig, mode: A.mode, count: items.length};
  if(stick) body.scrollTop = body.scrollHeight;
}

function openItemDetail(item){
  const ok = openInPanel(item.who === "op" ? "Operator command" : "Agent \u00B7 " + item.e.kind, function(root){
    if(item.who === "op"){
      const x = item.h;
      root.appendChild(h("h4", {text: "Command"}));
      root.appendChild(kv([["cmd", x.cmd || ""], ["args", x.args || ""], ["task", x.task_id || ""],
                           ["status", x.status || ""], ["queued", x.timestamp || ""]]));
      root.appendChild(h("h4", {text: "Raw output"}));
      root.appendChild(h("pre", {text: x.output == null ? "(none yet)" : String(x.output)}));
      return;
    }
    const e = item.e;
    root.appendChild(h("h4", {text: "Event"}));
    root.appendChild(kv([["seq", String(e.seq)], ["time", e.ts || ""], ["kind", e.kind || ""]]));
    root.appendChild(h("h4", {text: "Text"}));
    root.appendChild(h("pre", {text: e.text || ""}));
    root.appendChild(h("h4", {text: "Detail"}));
    root.appendChild(h("pre", {text: JSON.stringify(e.detail || {}, null, 2)}));
    // Honest about what the service sends: the stream carries a clipped
    // summary and a few fields, not the transcript.
    root.appendChild(h("div", {class: "ai-note",
      text: "The stream carries this summary only. Full tool arguments, raw tool output and the model exchange are not exposed by the agent service yet."}));
  });
  if(!ok) notify("info", item.who === "op" ? "Operator command" : "Agent " + item.e.kind,
                 item.who === "op" ? item.h.cmd : item.e.text, 6000);
}

// ── Rendering: drawer ──

function agentRenderDrawer(status){
  const d = document.querySelector(".ai-drawer");
  if(!d) return;
  const c = status || {};
  const max = (A.status && A.status.max_phase) || DEFAULT_MAX_PHASE;
  const title = d.querySelector(".ai-d-title");
  title.textContent = "";
  title.appendChild(document.createTextNode("\u25C6 Run " + A.rid));
  title.appendChild(h("span", {class: "ai-state " + (c.status || ""), text: c.status || "starting"}));

  const gauge = d.querySelector(".ai-d-gauge");
  const phase = Number(c.phase) || 0;
  gauge.firstChild.style.width = Math.min(100, Math.round(phase / max * 100)) + "%";

  const tok = (c.budgets && c.budgets.tokens) || {};
  const run = (c.budgets && c.budgets.runtime_seconds) || {};
  const tokHot = tok.limit && tok.used / tok.limit > 0.8;
  const runHot = run.limit && run.elapsed / run.limit > 0.8;
  const rows = d.querySelector(".ai-rows");
  rows.textContent = "";
  [["Phase", c.phase == null ? "-" : phase + " / " + max, false],
   ["Score", c.score == null ? "-" : String(c.score), false],
   ["Detections", c.detections == null ? "-" : String(c.detections), c.detections > 0],
   ["Tokens", fmtTokens(tok.used) + " / " + fmtTokens(tok.limit), tokHot],
   ["Runtime", fmtDuration(run.elapsed) + " / " + fmtDuration(run.limit), runHot],
  ].forEach(function(r){
    rows.appendChild(h("dt", {text: r[0]}));
    rows.appendChild(h("dd", {class: r[2] ? "warn" : null, text: r[1]}));
  });

  const warns = d.querySelector(".ai-d-warns");
  warns.textContent = "";
  if(A.campWarnings.length){
    warns.appendChild(h("div", {class: "ai-warns"}, h("b", {text: "OpSec"}),
      h("ul", {}, A.campWarnings.map(function(w){ return h("li", {text: String(w)}); }))));
  }
  if(A.pausePending && c.status !== "running") A.pausePending = false;
  renderPaneHead();
}

function renderLost(){
  const box = document.querySelector(".ai-d-lost");
  if(!box) return;
  box.textContent = "";
  if(A.note){
    box.appendChild(h("div", {class: "ai-lost", text: A.note}));
    return;
  }
  if(A.lost){
    box.appendChild(h("div", {class: "ai-lost"},
      "Lost contact with the agent service. The campaign may still be running there.",
      h("button", {type: "button", text: "Retry", onclick: resumePolling})));
  } else if(A.said){
    box.appendChild(h("div", {class: "ai-lost retrying"}, "The agent service is not answering; trying again with growing pauses."));
  }
}

// The card is rebuilt only when what it shows changes. The polls tick every
// 1.5s, and a button replaced between mouse-down and mouse-up swallows the click.
function renderKnocks(){
  const box = document.querySelector(".ai-d-knocks");
  if(!box) return;
  const sig = A.approvals.map(function(a){ return a.id + (A.answering[a.id] ? "*" : ""); }).join(",");
  if(sig === A.knockSig) return;
  A.knockSig = sig;
  box.textContent = "";
  A.approvals.forEach(function(ap, i){ box.appendChild(knockCard(ap, i + 1, A.approvals.length)); });
}

function evLine(ev){
  if(!ev || typeof ev.ev !== "number") return null;
  const t = ev.threshold == null ? 0 : ev.threshold;
  return fmtNum(ev.points, 0) + " \u00D7 " + fmtNum(ev.p_success_effective, 2) + " \u2212 "
    + fmtNum(ev.risk_coefficient, 0) + " \u00D7 " + fmtNum(ev.p_detect_effective, 2)
    + " = " + fmtNum(ev.ev, 1, true) + " (threshold " + fmtNum(t, 1, true) + ")";
}

function knockCard(ap, n, total){
  const cl = ap.classification || {};
  const ev = ap.ev || {};
  const busy = !!A.answering[ap.id];
  // Two reasons, because the operator decides from them: why this action is
  // gated at all (the classifier's), and why the arbiter's numbers come out
  // the way they do (the EV breakdown).
  const why1 = cl.reason || "no reason recorded";
  const notes = [];
  if(ev.detections != null) notes.push(ev.detections + " detection(s) so far");
  if(ev.p_detect_substituted) notes.push("no p_detect in the risk table, configured prior used");
  if(ev.override_decisive) notes.push("only the model's p_success override lifts it over the line");
  const line = evLine(ev);
  const num = typeof ev.ev === "number" ? ev.ev : null;
  return h("div", {class: "ai-knock"},
    h("div", {class: "ai-knock-head"}, h("span", {text: "\u26A0 Knock " + n + "/" + total}),
      h("span", {text: cl.phase ? "phase " + cl.phase : ""})),
    h("div", {class: "ai-action", text: (ap.action || "?") + (cl.action_class ? " [" + cl.action_class + "]" : "")}),
    h("div", {class: "ai-why"}, h("small", {text: "Why it asks"}), why1),
    h("div", {class: "ai-why"}, h("small", {text: "Why the numbers say so"}),
      line || "no EV was recorded for this request", notes.length ? " \u2014 " + notes.join("; ") : ""),
    h("div", {class: "ai-ev " + (num == null ? "" : num > 0 ? "pos" : "neg")},
      "EV ", h("b", {text: num == null ? "n/a" : fmtNum(num, 1, true)})),
    h("div", {class: "ai-ans"},
      h("button", {type: "button", class: "allow", text: "Allow", disabled: busy,
                   onclick: function(){ agentAnswerApproval(ap.id, true); }}),
      h("button", {type: "button", class: "deny", text: "Deny", disabled: busy,
                   onclick: function(){ agentAnswerApproval(ap.id, false); }})));
}

async function agentAnswerApproval(id, allowed){
  if(A.rid == null || A.answering[id]) return;
  A.answering[id] = true;
  renderKnocks();
  const r = await aiCall("campaign/" + A.rid + "/approve",
    {method: "POST", body: JSON.stringify({approval_id: id, allowed: allowed})});
  delete A.answering[id];
  if(r.ok){
    notify(allowed ? "success" : "info", allowed ? "Approved" : "Denied", "Your answer was sent to the agent.", 4000);
    A.approvals = A.approvals.filter(function(a){ return a.id !== id; });
  } else if(r.status === 404){
    // Answered elsewhere, or the agent gave up waiting: nothing left to decide.
    notify("warning", "Approval closed", "That request was already answered or has timed out.", 6000);
    A.approvals = A.approvals.filter(function(a){ return a.id !== id; });
  } else {
    // The card stays, so the operator can try again.
    notify("error", "Answer not delivered", reasonOf(r), 7000);
  }
  renderKnocks();
}

// ── Campaign controls ──

async function control(action){
  if(A.rid == null) return;
  const r = await aiCall("campaign/" + A.rid + "/" + action, {method: "POST", body: "{}"});
  if(!r.ok) notify("error", "Could not " + action, reasonOf(r), 6000);
  schedule("drawer", 0);
}

function onPause(){
  if(A.camp && A.camp.status === "paused") return control("resume");
  // A request, not an instant: the campaign reads "paused" once it reaches
  // its next model call, so say so rather than leave the button looking dead.
  A.pausePending = true;
  notify("info", "Pause requested", "The campaign pauses at its next step.", 4000);
  renderPaneHead();
  return control("pause");
}

function onStop(){
  if(!confirm("Stop campaign " + A.rid + "? Beacon intervals are restored and the run ends as aborted.")) return;
  return control("stop");
}

// ── Public surface (Task 16 builds on these) ──

function agentInit(){
  return (async function(){
    watchContent();
    ensureButton();
    await agentLoadStatus();
  })().catch(report);
}

window.agentInit = guard(agentInit);
window.agentOpenPanel = guard(agentOpenPanel);
window.agentRenderDrawer = guard(agentRenderDrawer);
window.agentRenderStream = guard(agentRenderStream);
window.agentAnswerApproval = guard(agentAnswerApproval);

// A deferred script runs after parsing, so "loading" only holds if someone
// loads it differently; handle both rather than depend on it.
if(document.readyState === "loading") document.addEventListener("DOMContentLoaded", window.agentInit);
else window.agentInit();

})();

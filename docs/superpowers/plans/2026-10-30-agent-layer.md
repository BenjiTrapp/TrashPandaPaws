# Autonome Agenten-Schicht — Implementierungsplan (Teil 1 von 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein LLM-gesteuerter Agent plant und führt mehrphasige Enumerations-Kampagnen über die bestehenden Raccoon-C2-Beacons und das serverseitige Werkzeugarsenal aus, während der Operator parallel weiterarbeiten kann.

**Architecture:** Eigener asyncio-Dienst (`software/agent/`) mit eigener SQLite-DB, der die Raccoon-C2-HTTP-API als Client treibt. Der C2 reicht ihn über dünne `/api/ai/*`-Proxy-Routen an das Browser-GUI durch; `server.py` importiert nichts aus `software/agent/`. Orchestrator-LLM zerlegt Kampagnen in Tasks, Executor-LLMs führen sie aus, ein Router klassifiziert jede Aktion und ruft bei OpSec-/Resilienz-Relevanz ein Gate, das im überwachten Modus den Operator und im Full-Auto eine EV-Rechnung fragt.

**Tech Stack:** Python 3.9, asyncio, aiohttp (Dienst), `anthropic` + `openai` SDKs (vier Anbieter über zwei Protokolle), stdlib `sqlite3` mit FTS5, `croniter`, stdlib `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-30-autonomous-agent-layer-design.md`

**Umfang dieses Plans:** Abschnitte 7–14 und 17–19 der Spec (die Agenten-Schicht). Die Teilprojekte Wire Intel (§15) und Wifi-Kette (§16) sind eigene Pläne und werden gegen die hier entstehenden Capability- und Tool-Interfaces geschrieben.

## Global Constraints

- **Zielversion Python 3.9.** Kein `match`, kein `X | Y` in Laufzeit-Annotationen, kein `asyncio.TaskGroup` (stattdessen `asyncio.gather(..., return_exceptions=True)`), kein `tomllib` (Konfiguration in YAML).
- **`software/c2/server.py` darf nichts aus `software/agent/` importieren.** Kopplung ausschließlich über HTTP. Der Proxy nutzt `urllib` aus der Standardbibliothek — keine neue Abhängigkeit im C2-Image.
- **Tests:** stdlib `unittest`, Dateien unter `software/tests/`, ausführbar per `python -m unittest software.tests.<modul>`. Kein pytest.
- **Zeitstempel durchgängig RFC3339-TEXT in UTC** (`datetime.now(timezone.utc).isoformat()`).
- **Fehler sind Werte, keine Ausnahmen**, sobald ein LLM sie sieht: Dispatch liefert `[ERROR] …`-Strings, Tools liefern `{"success": false, …}`, das Gate liefert `{"allowed": false, "reason": …}`.
- **Ausgabe-Kürzung:** Kopf 2000 + Markierung + Schwanz 2000 **Zeichen** (nicht Bytes), Markierung `\n\n[... OUTPUT TRUNCATED (N chars total) ...]\n\n`.
- **Der Agent darf `/api/server/exec` ausschließlich in der argv-Form aufrufen**, niemals mit `cmd`-String.
- **Jede Änderung an `server.py` und `beacon.py` muss einzeln verhaltensneutral sein**, wenn kein Agent existiert (Spec §19.3, §19.4).
- Namenskonvention des Repos: `snake_case`, führender `_` für modulprivate Helfer, Abschnittsbanner `# ── … ──`, `%`-Formatierung für Logger-Aufrufe.
- API-Keys nie in YAML im Repo; nur Umgebungsvariable oder Datei mit `0600`.

## Review Focus

Fünf Eingabeklassen, die die Spec voraussetzt, die aber ohne gezielten Test durchfallen würden. Jede ist unten dem Task zugeordnet, der den Code besitzt.

1. **Ein Ziel, das die Scope-Prüfung nicht auflösen kann, muss abgelehnt werden — nicht durchgelassen.** Die gefährliche Eingabe ist kein böswilliges Ziel, sondern ein unerwartetes Format: `10.0.1.0/24,10.0.2.0/24` in einem Argument, `-iL ziele.txt`, ein Hostname ohne Fund-Zuordnung, ein IPv6-Literal in Klammern. Fail-open macht die stärkste Zusage der Spec zur Behauptung. → Task 3.
2. **Das LLM wird versuchen, das Gate zu umgehen, ohne es zu wollen** — etwa indem es `nxc smb 10.0.1.5 -M lsassy` statt `lsassy` schreibt, oder `persist` als `shell crontab -e`-Variante. Die Klassifikation muss auf Wirkung prüfen, nicht auf Binärnamen. → Task 2.
3. **Ein Beacon, der mitten in der Kampagne offline geht**, darf nicht dazu führen, dass ein Executor ewig pollt und das Semaphor hält. → Task 10.
4. **Ein LLM, das kaputtes Tool-Calling liefert** — unbekannter Tool-Name, fehlendes Pflichtargument, JSON-Syntaxfehler im Argument-Blob, zwei Aufrufe desselben Tools mit widersprüchlichen Argumenten. Die Schleife muss weiterlaufen und dem Modell einen lesbaren Fehler zurückgeben. → Task 6.
5. **Ein Absturz des Agenten-Dienstes bei abgesenktem Beacon-Intervall** lässt den Beacon dauerhaft auf 15 s laut laufen. Der Dienst muss beim Start Waisen erkennen und zurücksetzen. → Task 13.

---

## File Structure

**Neuer Agenten-Dienst** — jede Datei eine Verantwortung, keine über ~400 Zeilen:

| Datei | Verantwortung |
|---|---|
| `software/agent/config.py` | Auflösungskaskade CLI > YAML > Env > Vorbelegung, Fähigkeitsstufen-Zuordnung |
| `software/agent/store/schema.sql` | Vollständige DDL, ein `executescript`-Batch |
| `software/agent/store/db.py` | Verbindung, Pragmas, FTS5-Probe mit LIKE-Rückfall |
| `software/agent/store/queries.py` | Alle SQL-Zugriffe als Funktionen |
| `software/agent/safety.py` | Metazeichen, Stufe-1-Blocklist, Scan-Limits, Risikotabelle, Aktionsklassifikation |
| `software/agent/scope.py` | Ziel-Extraktion und fail-closed-Auflösung |
| `software/agent/gate.py` | Approval-Mechanik, EV-Schiedsrichter, Detection-Nachführung |
| `software/agent/llm/provider.py` | `create_client()`, Anbieter-Matrix, Fähigkeitsstufen |
| `software/agent/llm/anthropic_client.py` | Anthropic-Messages-Protokoll |
| `software/agent/llm/openai_client.py` | OpenAI-kompatibel: OpenRouter, OpenCode Zen, Ollama, LM Studio |
| `software/agent/llm/loop.py` | Tool-Calling-Schleife, Turn-Budget, Kürzung, Text-Protokoll-Fallback |
| `software/agent/llm/mock.py` | Mock-Modell mit Antwortwarteschlange für Tests |
| `software/agent/c2client.py` | Typisierter Client für die Raccoon-API |
| `software/agent/executor/beacon.py` | Ausführung über die Agent-Lane |
| `software/agent/executor/server_tool.py` | Ausführung auf der C2-Box via argv |
| `software/agent/executor/router.py` | Pfadwahl, Klassifikation, Gate-Aufruf, Detection-Erkennung |
| `software/agent/prompts.py` | Orchestrator- und Executor-Preamble |
| `software/agent/tools/*.py` | Ein Modul je Tool, plus `registry.py` mit den Faktoren |
| `software/agent/orchestrator.py` | Kampagnen-Lebenszyklus, Dispatch, Pause/Resume, Waisen-Erkennung |
| `software/agent/scheduler.py` | Cron-Poll-Schleife mit Überlappungssperre |
| `software/agent/service.py` | aiohttp-App und Endpunkte |
| `software/agent/__main__.py` | CLI-Einstiegspunkt |

**Änderungen am Bestand:**

| Datei | Änderung |
|---|---|
| `software/c2/server.py` | Task-Lanes, Batching, `tool_runs`, argv-Form, Timeout, Proxy-Routen |
| `software/c2/beacon.py` | `caps`-Meldung, Batch-Verarbeitung |
| `software/c2/beacon_standalone.py` | `caps`-Meldung |
| `software/c2/static/agent.css` | Stile der drei Regionen und des Formulars |
| `software/c2/static/agent.js` | Gesamte Agenten-Oberfläche, fügt den Knopf selbst ein |
| `configs/raccoon.yaml` | `agent:`-Block, Sliver-Hinweis |
| `software/main.py` | Warnung bei Sliver + Agenten-Block |
| `software/c2/Dockerfile` | COPY-Liste |
| `software/agent/Dockerfile` | Neues schlankes Image, Repo-Root-Kontext |
| `docker-compose.yml` | Zweiter Service |

**Reihenfolge-Logik:** Tasks 1–8 bauen das Fundament ohne jede Abhängigkeit zum C2 und sind vollständig isoliert testbar. Tasks 9–10 ändern den Bestand rückwärtskompatibel. Tasks 11–14 verdrahten die Schleife. Tasks 15–16 die Oberfläche. Tasks 17–19 Betrieb, Auslieferung und die Status-quo-Absicherung.

---

### Task 1: Datenhaltung

**Files:**
- Create: `software/agent/__init__.py`, `software/agent/store/__init__.py`, `software/agent/store/schema.sql`, `software/agent/store/db.py`, `software/agent/store/queries.py`
- Test: `software/tests/test_agent_store.py`

**Interfaces:**
- Consumes: nichts
- Produces:
  - `db.open_store(path: str) -> sqlite3.Connection` — Pragmas `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `temp_store=MEMORY`; legt Schema an
  - `db.has_fts5(conn) -> bool`
  - `queries.create_run(conn, trigger_type, trigger_data, mode, config_json) -> int`
  - `queries.set_run_status(conn, run_id, status) -> None`
  - `queries.set_run_phase(conn, run_id, phase: int) -> None`
  - `queries.get_run(conn, run_id) -> Optional[dict]`
  - `queries.list_unfinished_runs(conn) -> List[dict]`
  - `queries.create_task(conn, run_id, name, description, lane, phase) -> int`
  - `queries.update_task(conn, task_id, status, result) -> None`
  - `queries.log_finding(conn, run_id, host, finding_type, data, source) -> int`
  - `queries.get_findings_by_host(conn, host) -> List[dict]`
  - `queries.log_score(conn, run_id, action, points, risk_level, detected) -> int`
  - `queries.get_score_context(conn, run_id) -> dict` mit `total_score`, `detection_count`, `recent_events` (letzte 5)
  - `queries.get_run_summary(conn, run_id) -> dict` mit `task_count`, `completed_task_count`, `failed_task_count`, `finding_count`, `total_score`, `detection_count`, `phase`
  - `queries.create_approval(conn, run_id, action, classification_json, ev_json) -> int`
  - `queries.decide_approval(conn, approval_id, decision, decided_by) -> None`
  - `queries.get_pending_approvals(conn, run_id) -> List[dict]`
  - `queries.save_memory(conn, scope_key, topic_key, content, sector) -> int`
  - `queries.search_memory(conn, scope_key, query, limit) -> List[dict]` — verstärkt `salience` um 0.1, Deckel 5.0
  - `queries.run_decay_sweep(conn) -> int` — Anzahl gelöschter Einträge
  - `queries.save_script(conn, name, code, language, description, tags) -> int` — Upsert auf `name`
  - `queries.search_scripts(conn, query, limit) -> List[dict]`
  - `queries.get_script_by_name(conn, name) -> Optional[dict]`
  - `queries.log_llm_interaction(conn, **felder) -> int`
  - `queries.get_run_token_summary(conn, run_id) -> dict`

- [ ] **Step 1: Write the failing tests**

```python
class TestSchema(unittest.TestCase):
    def test_open_store_creates_all_tables(self):
        conn = db.open_store(":memory:")
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("runs", "tasks", "findings", "score_events", "approvals",
                  "memories", "scripts", "scheduled_tasks", "cve_cache",
                  "llm_interactions"):
            self.assertIn(t, names)

    def test_foreign_keys_enforced(self):
        conn = db.open_store(":memory:")
        with self.assertRaises(sqlite3.IntegrityError):
            queries.create_task(conn, 9999, "t", "d", "agent", 1)

class TestRunLifecycle(unittest.TestCase):
    def test_run_status_and_phase_roundtrip(self):
        conn = db.open_store(":memory:")
        rid = queries.create_run(conn, "campaign", "10.0.1.0/24", "supervised", "{}")
        queries.set_run_phase(conn, rid, 3)
        queries.set_run_status(conn, rid, "paused")
        run = queries.get_run(conn, rid)
        self.assertEqual(run["phase"], 3)
        self.assertEqual(run["status"], "paused")

    def test_list_unfinished_runs_includes_running_and_paused_only(self):
        conn = db.open_store(":memory:")
        a = queries.create_run(conn, "campaign", None, "auto", "{}")
        b = queries.create_run(conn, "campaign", None, "auto", "{}")
        c = queries.create_run(conn, "campaign", None, "auto", "{}")
        queries.set_run_status(conn, b, "paused")
        queries.set_run_status(conn, c, "completed")
        self.assertEqual({r["id"] for r in queries.list_unfinished_runs(conn)}, {a, b})

class TestScoring(unittest.TestCase):
    def test_score_context_totals_and_detection_count(self):
        conn = db.open_store(":memory:")
        rid = queries.create_run(conn, "campaign", None, "auto", "{}")
        queries.log_score(conn, rid, "service_identified", 15, "low", False)
        queries.log_score(conn, rid, "detection", -100, "high", True)
        ctx = queries.get_score_context(conn, rid)
        self.assertEqual(ctx["total_score"], -85)
        self.assertEqual(ctx["detection_count"], 1)

    def test_recent_events_capped_at_five_newest_first(self):
        conn = db.open_store(":memory:")
        rid = queries.create_run(conn, "campaign", None, "auto", "{}")
        for i in range(7):
            queries.log_score(conn, rid, "port_found", 5, "low", False)
        ctx = queries.get_score_context(conn, rid)
        self.assertEqual(len(ctx["recent_events"]), 5)

class TestMemory(unittest.TestCase):
    def test_search_reinforces_salience(self):
        conn = db.open_store(":memory:")
        queries.save_memory(conn, "run:1", None, "SMB signing disabled on dc01", "semantic")
        queries.search_memory(conn, "run:1", "smb signing", 10)
        row = conn.execute("SELECT salience FROM memories").fetchone()
        self.assertAlmostEqual(row[0], 1.1, places=5)

    def test_salience_reinforcement_capped_at_five(self):
        conn = db.open_store(":memory:")
        queries.save_memory(conn, "run:1", None, "target host", "semantic")
        conn.execute("UPDATE memories SET salience = 4.95")
        queries.search_memory(conn, "run:1", "target", 10)
        self.assertAlmostEqual(
            conn.execute("SELECT salience FROM memories").fetchone()[0], 5.0, places=5)

    def test_decay_sweep_only_touches_entries_older_than_a_day(self):
        conn = db.open_store(":memory:")
        old = queries.save_memory(conn, "s", None, "old entry", "episodic")
        new = queries.save_memory(conn, "s", None, "new entry", "episodic")
        conn.execute("UPDATE memories SET created_at = ? WHERE id = ?",
                     (_iso_days_ago(3), old))
        queries.run_decay_sweep(conn)
        sal = dict(conn.execute("SELECT id, salience FROM memories").fetchall())
        self.assertAlmostEqual(sal[old], 0.98, places=5)
        self.assertAlmostEqual(sal[new], 1.0, places=5)

    def test_decay_sweep_prunes_below_threshold(self):
        conn = db.open_store(":memory:")
        queries.save_memory(conn, "s", None, "faded", "episodic")
        conn.execute("UPDATE memories SET salience = 0.05, created_at = ?",
                     (_iso_days_ago(3),))
        self.assertEqual(queries.run_decay_sweep(conn), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)

    def test_search_falls_back_to_like_without_fts5(self):
        conn = db.open_store(":memory:")
        queries.save_memory(conn, "s", None, "kerberoasting candidate found", "semantic")
        with unittest.mock.patch.object(db, "has_fts5", return_value=False):
            hits = queries.search_memory(conn, "s", "kerberoasting", 10)
        self.assertEqual(len(hits), 1)

class TestScripts(unittest.TestCase):
    def test_save_script_upserts_on_name(self):
        conn = db.open_store(":memory:")
        queries.save_script(conn, "sweep", "echo a", "bash", "first", "[]")
        queries.save_script(conn, "sweep", "echo b", "bash", "second", "[]")
        rows = conn.execute("SELECT code, description FROM scripts").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "echo b")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_store -v`
Expected: FAIL mit `ModuleNotFoundError: No module named 'software.agent'`

- [ ] **Step 3: Write `software/agent/store/schema.sql`**

Die vollständige DDL aus Spec §11. Alle Zeitstempel `TEXT NOT NULL` im RFC3339-Format. `runs.status` mit `CHECK(status IN ('running','paused','completed','failed','aborted'))`, `runs.phase INTEGER`. `tasks.lane` mit `CHECK(lane IN ('operator','agent'))`. `memories.sector` mit `CHECK(sector IN ('semantic','episodic'))`. `approvals.decided_by` mit `CHECK(decided_by IN ('operator','ev','timeout'))`. `llm_interactions.status` mit `CHECK(status IN ('success','error'))`. Fremdschlüssel von `tasks`, `findings`, `score_events`, `approvals`, `llm_interactions` auf `runs(id)`. Zwei FTS5-Tabellen als External-Content (`content=memories, content_rowid=id` bzw. `content=scripts, content_rowid=id`) mit je drei Triggern für Insert, Update und Delete — beim Update muss die `'delete'`-Zeile **vor** der Neueinfügung stehen. Indizes auf `memories(scope_key)`, `memories(salience)`, `scripts(name)`, `llm_interactions(run_id)`, `scheduled_tasks(status, next_run)`.

Die Wire- und Wifi-Tabellen aus §11 gehören **nicht** in diesen Plan — sie kommen mit ihren Teilprojekten.

- [ ] **Step 4: Implement `software/agent/store/db.py`**

`open_store` führt die Pragmas aus, lädt `schema.sql` per `importlib.resources` oder `Path(__file__).parent`, und führt sie mit `executescript` aus. `row_factory = sqlite3.Row`. `has_fts5` probiert eine Virtual-Table-Anlage in einer Transaktion und macht sie rückgängig; Ergebnis wird modulweit gecacht.

- [ ] **Step 5: Implement `software/agent/store/queries.py`**

Alle Funktionen aus dem Interfaces-Block. Zwei Festlegungen, die Tests und Signatur nicht hergeben:

Verfallslauf (Spec §11):
```python
DECAY_FACTOR = 0.98
PRUNE_THRESHOLD = 0.1
DECAY_AGE_SECONDS = 86400
```
Erst `UPDATE memories SET salience = salience * 0.98 WHERE created_at < <cutoff>`, dann `DELETE FROM memories WHERE salience < 0.1`, Rückgabe ist `cursor.rowcount` des DELETE.

FTS5-Suchanfrage: Eingabe mit `re.sub(r"[^\w\s]", " ", query)` säubern, an Leerzeichen trennen, bei leerem Ergebnis `[]` zurückgeben, sonst Präfix-Anfrage `w1* OR w2* OR …` bauen. Ohne FTS5 stattdessen `LIKE '%wort%'` je Wort mit `OR` verknüpft. Sortierung in beiden Fällen `ORDER BY salience DESC LIMIT ?`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_store -v`
Expected: PASS, alle Tests

- [ ] **Step 7: Commit**

```bash
git add software/agent/__init__.py software/agent/store/ software/tests/test_agent_store.py
git commit -m "feat(agent): add SQLite store with FTS5 fallback and salience decay"
```

---

### Task 2: Safety — Blocklist, Scan-Limits, Risikotabelle

**Files:**
- Create: `software/agent/safety.py`
- Test: `software/tests/test_agent_safety.py`

**Interfaces:**
- Consumes: nichts
- Produces:
  - `TIER_HARD = 1`, `TIER_KNOCK = 2`, `TIER_FREE = 3`
  - `Classification` — `NamedTuple` mit `tier: int`, `action_key: str`, `action_class: str`, `points: int`, `p_success: float`, `p_detect: float`, `phase: int`, `reason: str`
  - `safety.has_shell_metachars(command: str) -> bool`
  - `safety.classify(command: str, *, target_kind: str, is_uplink_iface: Callable[[str], bool], phase5_enabled: bool) -> Classification` — `target_kind` ist `"beacon"`, `"dropbox"` oder `"server"`
  - `safety.enforce_scan_limits(command: str) -> str`
  - `safety.validate_script(code: str, language: str) -> Optional[str]` — Fehlermeldung oder `None`
  - `safety.clamp_llm_adjustment(prior: float, proposed: float) -> float` — ±0.2 um den Prior, zusätzlich auf [0.01, 0.99] begrenzt
  - `safety.RISK_TABLE: Dict[str, Classification]`

- [ ] **Step 1: Write the failing tests**

```python
class TestMetachars(unittest.TestCase):
    def test_rejects_each_metacharacter(self):
        for bad in ("ls; rm -rf /", "a | b", "a && b", "a `id`", "a $(id)",
                    "a > f", "a\nb", "a & b"):
            self.assertTrue(safety.has_shell_metachars(bad), bad)

    def test_accepts_plain_command_with_flags(self):
        self.assertFalse(safety.has_shell_metachars("nmap -sV -p 445 10.0.1.5"))

class TestTierOne(unittest.TestCase):
    def _c(self, cmd, **kw):
        kw.setdefault("target_kind", "beacon")
        kw.setdefault("is_uplink_iface", lambda n: n == "eth0")
        kw.setdefault("phase5_enabled", True)
        return safety.classify(cmd, **kw)

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

class TestScriptValidation(unittest.TestCase):
    def test_rejects_script_whose_any_line_is_blocked(self):
        code = "echo start\nrm -rf /opt/raccoon\necho done"
        self.assertIsNotNone(safety.validate_script(code, "bash"))

    def test_accepts_benign_script(self):
        self.assertIsNone(safety.validate_script("nmap -sn 10.0.1.0/24\nwhoami", "bash"))

class TestClamp(unittest.TestCase):
    def test_clamps_to_plus_minus_two_tenths(self):
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.95), 0.70)
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.05), 0.30)
        self.assertAlmostEqual(safety.clamp_llm_adjustment(0.50, 0.55), 0.55)

    def test_never_leaves_probability_range(self):
        self.assertLessEqual(safety.clamp_llm_adjustment(0.95, 1.5), 0.99)
        self.assertGreaterEqual(safety.clamp_llm_adjustment(0.05, -1.0), 0.01)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_safety -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/safety.py`**

Signatur und Tests legen das Verhalten fest. Vier Dinge, die sie nicht hergeben:

**Die Klassifikation prüft Wirkung, nicht Binärnamen** (Review Focus 2). Umsetzung: eine Liste von `(regex, action_key)`-Paaren, die auf die **gesamte normalisierte Befehlszeile** angewendet wird — kleingeschrieben, Mehrfach-Leerzeichen zusammengefasst, `sudo` und Pfadpräfixe entfernt. Ein Treffer liefert den `action_key`, über den die `RISK_TABLE` nachgeschlagen wird. Beispielmuster für `lsass_dump`: `r"\blsass(y|\.exe|\.dmp)?\b|\bsecretsdump\b|\bprocdump\b.*\blsass\b|-M\s+lsassy"`. Reihenfolge zählt: Stufe-1-Muster werden vor Stufe-2-Mustern geprüft, damit `unpersist` nicht als `persist` durchgeht.

**`RISK_TABLE`** aus Spec §10.5, mindestens die dort genannten Zeilen (`lsass_dump`, `responder`, `ntlm_relay`, `persist`, `deauth`, `exploit_known_poc`), jede mit `action_class`, `points`, `p_success`, `p_detect`, `phase`. Ein Stufe-2-Treffer ohne Tabelleneintrag fällt auf einen konservativen Prior zurück: `points=25, p_success=0.3, p_detect=0.6`.

**Scan-Limits:** erst `re.sub(r"\s-T[0-5]\b", "", cmd)` und `re.sub(r"\s--max-rate\s+\d+", "", cmd)`, dann `cmd.replace("nmap", "nmap -T2 --max-rate 50", 1)`. Der Binärname wird über seinen Basenamen erkannt, damit `/usr/bin/nmap` und `sudo nmap` greifen.

**`validate_script`** trennt an Zeilenumbrüchen, überspringt Leerzeilen und Kommentarzeilen, und ruft für jede Restzeile `has_shell_metachars` sowie die Stufe-1-Prüfung. Die erste blockierte Zeile liefert die Meldung mit Zeilennummer.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_safety -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/safety.py software/tests/test_agent_safety.py
git commit -m "feat(agent): add safety classification, scan limits and risk table"
```

---

### Task 3: Scope — fail-closed

**Files:**
- Create: `software/agent/scope.py`
- Test: `software/tests/test_agent_scope.py`

**Interfaces:**
- Consumes: `queries.get_findings_by_host` (Task 1) für die Hostnamen-Auflösung
- Produces:
  - `Scope` — Klasse, `Scope(allow: List[str], deny: List[str])`
  - `scope.extract_targets(command: str) -> Tuple[List[str], List[str]]` — `(erkannte_ziele, nicht_auflösbare_argumente)`
  - `Scope.check(command: str, resolve_host: Callable[[str], Optional[str]]) -> Optional[str]` — Ablehnungsgrund oder `None`

- [ ] **Step 1: Write the failing tests**

```python
ALLOW = ["10.0.1.0/24", "10.0.2.0/24"]
DENY = ["10.0.9.0/24"]

def _scope():
    return scope.Scope(allow=ALLOW, deny=DENY)

class TestExtraction(unittest.TestCase):
    def test_extracts_plain_ipv4(self):
        found, unknown = scope.extract_targets("nmap -sV 10.0.1.5")
        self.assertEqual(found, ["10.0.1.5"])
        self.assertEqual(unknown, [])

    def test_extracts_cidr(self):
        found, _ = scope.extract_targets("netscan 10.0.1.0/24")
        self.assertEqual(found, ["10.0.1.0/24"])

    def test_extracts_both_range_forms(self):
        self.assertEqual(scope.extract_targets("nmap 10.0.1.1-254")[0], ["10.0.1.1-254"])
        self.assertEqual(
            scope.extract_targets("nmap 10.0.1.1-10.0.1.254")[0], ["10.0.1.1-10.0.1.254"])

    def test_comma_separated_targets_are_split(self):
        """Review Focus 1: unerwartetes Format, nicht böswilliges Ziel."""
        found, unknown = scope.extract_targets("nmap 10.0.1.5,10.0.2.7")
        self.assertEqual(found, ["10.0.1.5", "10.0.2.7"])
        self.assertEqual(unknown, [])

    def test_bracketed_ipv6_literal_is_recognised(self):
        found, unknown = scope.extract_targets("nmap -6 [fd00::1]")
        self.assertEqual(found, ["fd00::1"])
        self.assertEqual(unknown, [])

class TestFailClosed(unittest.TestCase):
    def test_target_file_argument_is_rejected(self):
        for cmd in ("nmap -iL ziele.txt 10.0.1.5",
                    "nxc smb targets.txt -u a -p b",
                    "nmap --target-file /tmp/t"):
            self.assertIsNotNone(_scope().check(cmd, lambda h: None), cmd)

    def test_hostname_without_finding_is_rejected(self):
        self.assertIsNotNone(_scope().check("nmap -sV dc01.corp.local", lambda h: None))

    def test_hostname_with_in_scope_finding_is_allowed(self):
        self.assertIsNone(
            _scope().check("nmap -sV fs02.corp.local", lambda h: "10.0.1.20"))

    def test_hostname_resolving_outside_scope_is_rejected(self):
        self.assertIsNotNone(
            _scope().check("nmap -sV dc01.corp.local", lambda h: "10.0.9.1"))

    def test_command_without_any_target_is_allowed(self):
        self.assertIsNone(_scope().check("whoami", lambda h: None))

    def test_in_scope_target_is_allowed(self):
        self.assertIsNone(_scope().check("nmap -sV 10.0.1.5", lambda h: None))

    def test_out_of_scope_target_is_rejected(self):
        self.assertIsNotNone(_scope().check("nmap -sV 172.16.0.5", lambda h: None))

    def test_cidr_wider_than_allowlist_is_rejected(self):
        self.assertIsNotNone(_scope().check("netscan 10.0.0.0/8", lambda h: None))

    def test_range_crossing_scope_boundary_is_rejected(self):
        self.assertIsNotNone(
            _scope().check("nmap 10.0.1.250-10.0.9.5", lambda h: None))

    def test_deny_beats_allow(self):
        s = scope.Scope(allow=["10.0.0.0/16"], deny=["10.0.9.0/24"])
        self.assertIsNone(s.check("nmap 10.0.1.5", lambda h: None))
        self.assertIsNotNone(s.check("nmap 10.0.9.5", lambda h: None))

    def test_mixed_targets_reject_if_any_is_out_of_scope(self):
        self.assertIsNotNone(
            _scope().check("nmap 10.0.1.5,172.16.0.5", lambda h: None))

    def test_rejection_reason_names_the_offending_target(self):
        reason = _scope().check("nmap -sV 172.16.0.5", lambda h: None)
        self.assertIn("172.16.0.5", reason)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_scope -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/scope.py`**

Der Kern ist die Extraktion. Vorgehen: Befehlszeile an Leerzeichen trennen, jedes Argument zusätzlich an Kommas trennen, umgebende eckige Klammern entfernen. Für jedes Token in dieser Reihenfolge prüfen: `ipaddress.ip_address`, `ipaddress.ip_network(strict=False)`, die zwei Bereichsformen per Regex, dann Hostname-Muster `^[a-zA-Z0-9._-]+$` mit mindestens einem Punkt oder einem Treffer in `findings`. Tokens, die mit `-` beginnen, sind Flags und werden übersprungen — **mit einer Ausnahme:** `-iL`, `--target-file`, `--targets` und `-` machen die Prüfung sofort unauflösbar, ebenso ein Argument, das auf `.txt`, `.lst` oder `.list` endet.

`check` löst Hostnamen über `resolve_host` auf, wandelt alle erkannten Ziele in `ip_network`-Objekte (Bereiche über `ipaddress.summarize_address_range`), und verlangt für jedes: in mindestens einem Allow-Netz **enthalten** (`subnet_of`) und in keinem Deny-Netz überlappend. Nicht auflösbare Argumente führen immer zur Ablehnung mit dem Hinweis, Ziele einzeln zu benennen.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_scope -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/scope.py software/tests/test_agent_scope.py
git commit -m "feat(agent): add fail-closed scope enforcement"
```

---

### Task 4: Gate — Approvals, EV-Schiedsrichter, Detection-Nachführung

**Files:**
- Create: `software/agent/gate.py`
- Test: `software/tests/test_agent_gate.py`

**Interfaces:**
- Consumes: `safety.Classification`, `safety.TIER_*`, `safety.clamp_llm_adjustment` (Task 2); `queries.create_approval`, `queries.decide_approval`, `queries.log_score`, `queries.get_score_context` (Task 1)
- Produces:
  - `GateDecision` — `NamedTuple` mit `allowed: bool`, `reason: str`, `decided_by: str`, `ev: Optional[float]`
  - `Gate(conn, run_id, *, mode, ev_threshold, p_detect_prior, detection_budget, unattended_behavior, approval_timeout)` — `mode` ist `"supervised"` oder `"auto"`, `unattended_behavior` ist `"decide"`, `"skip"` oder `"pause"`
  - `await Gate.request(classification, *, p_success_override=None) -> GateDecision`
  - `Gate.answer(approval_id: int, allowed: bool) -> bool` — löst ein wartendes `request` auf
  - `Gate.pending() -> List[dict]`
  - `Gate.effective_p_detect(prior: float) -> float`
  - `Gate.note_detection(source: str) -> bool` — `True`, wenn das Budget erschöpft ist
  - `Gate.detection_count -> int`
  - `gate.scan_for_detection(output: str, *, host_was_responsive: bool) -> Optional[str]` — Musterbezeichnung oder `None`
  - `GatePauseRequested` — Exception, wenn `unattended_behavior == "pause"` greift

- [ ] **Step 1: Write the failing tests**

```python
def _cls(tier=safety.TIER_KNOCK, points=50, p_success=0.5, p_detect=0.7):
    return safety.Classification(tier=tier, action_key="lsass_dump",
                                 action_class="credential_access", points=points,
                                 p_success=p_success, p_detect=p_detect,
                                 phase=4, reason="LSASS-Zugriff")

def _gate(conn, rid, **kw):
    kw.setdefault("mode", "auto")
    kw.setdefault("ev_threshold", 0.0)
    kw.setdefault("p_detect_prior", 0.15)
    kw.setdefault("detection_budget", 3)
    kw.setdefault("unattended_behavior", "decide")
    kw.setdefault("approval_timeout", 0.2)
    return gate.Gate(conn, rid, **kw)

class TestTierRouting(IsolatedAsyncioTestCase):
    async def test_tier_three_passes_without_approval_row(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(tier=safety.TIER_FREE))
        self.assertTrue(d.allowed)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)

    async def test_tier_one_is_refused_even_in_auto_mode(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(tier=safety.TIER_HARD))
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "hard")

    async def test_tier_one_cannot_be_approved_by_operator(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised")
        d = await g.request(_cls(tier=safety.TIER_HARD))
        self.assertFalse(d.allowed)
        self.assertEqual(g.pending(), [])

class TestEvArbiter(IsolatedAsyncioTestCase):
    async def test_positive_ev_proceeds(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(points=200, p_success=0.6, p_detect=0.3))
        self.assertTrue(d.allowed)
        self.assertEqual(d.decided_by, "ev")
        self.assertAlmostEqual(d.ev, 200 * 0.6 - 100 * 0.3)

    async def test_negative_ev_is_refused(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(_cls(points=50, p_success=0.5, p_detect=0.7))
        self.assertFalse(d.allowed)
        self.assertAlmostEqual(d.ev, 50 * 0.5 - 100 * 0.7)

    async def test_threshold_is_respected(self):
        conn, rid = _fresh_run()
        c = _cls(points=100, p_success=0.5, p_detect=0.4)   # EV = 10
        self.assertTrue((await _gate(conn, rid, ev_threshold=5.0).request(c)).allowed)
        self.assertFalse((await _gate(conn, rid, ev_threshold=20.0).request(c)).allowed)

    async def test_llm_p_success_override_is_clamped(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid).request(
            _cls(points=50, p_success=0.5, p_detect=0.1), p_success_override=0.99)
        self.assertAlmostEqual(d.ev, 50 * 0.7 - 100 * 0.1)

    async def test_decision_is_persisted(self):
        conn, rid = _fresh_run()
        await _gate(conn, rid).request(_cls())
        row = conn.execute(
            "SELECT decision, decided_by FROM approvals").fetchone()
        self.assertEqual(row["decided_by"], "ev")

class TestDetectionTracking(unittest.TestCase):
    def test_p_detect_rises_by_fifteen_hundredths_per_detection(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid)
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.30)
        g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.45)
        g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.60)

    def test_p_detect_is_capped(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=99)
        for _ in range(20):
            g.note_detection("reset")
        self.assertAlmostEqual(g.effective_p_detect(0.30), 0.95)

    def test_budget_exhaustion_is_reported(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, detection_budget=2)
        self.assertFalse(g.note_detection("reset"))
        self.assertTrue(g.note_detection("reset"))

    def test_detection_is_scored_as_minus_hundred(self):
        conn, rid = _fresh_run()
        _gate(conn, rid).note_detection("reset")
        self.assertEqual(queries.get_score_context(conn, rid)["total_score"], -100)

class TestDetectionScanner(unittest.TestCase):
    def test_recognises_known_patterns(self):
        for out in ("connection reset by peer", "blocked by policy",
                    "denied by policy", "Connection closed by remote host"):
            self.assertIsNotNone(gate.scan_for_detection(out, host_was_responsive=True), out)

    def test_no_route_only_counts_after_prior_contact(self):
        out = "No route to host"
        self.assertIsNotNone(gate.scan_for_detection(out, host_was_responsive=True))
        self.assertIsNone(gate.scan_for_detection(out, host_was_responsive=False))

    def test_clean_output_is_not_a_detection(self):
        self.assertIsNone(gate.scan_for_detection(
            "445/tcp open microsoft-ds", host_was_responsive=True))

class TestSupervisedMode(IsolatedAsyncioTestCase):
    async def test_operator_approval_releases_the_waiter(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        await asyncio.sleep(0.05)
        pending = g.pending()
        self.assertEqual(len(pending), 1)
        g.answer(pending[0]["id"], True)
        d = await task
        self.assertTrue(d.allowed)
        self.assertEqual(d.decided_by, "operator")

    async def test_operator_refusal_returns_reason_for_the_llm(self):
        conn, rid = _fresh_run()
        g = _gate(conn, rid, mode="supervised", approval_timeout=5.0)
        task = asyncio.create_task(g.request(_cls()))
        await asyncio.sleep(0.05)
        g.answer(g.pending()[0]["id"], False)
        d = await task
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason)

    async def test_timeout_records_timeout_as_decider(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, mode="supervised", approval_timeout=0.1).request(_cls())
        self.assertFalse(d.allowed)
        self.assertEqual(d.decided_by, "timeout")

class TestUnattendedBehaviour(IsolatedAsyncioTestCase):
    async def test_skip_refuses_without_ev(self):
        conn, rid = _fresh_run()
        d = await _gate(conn, rid, unattended_behavior="skip").request(
            _cls(points=200, p_success=0.9, p_detect=0.1))
        self.assertFalse(d.allowed)
        self.assertIsNone(d.ev)

    async def test_pause_raises_for_the_lifecycle(self):
        conn, rid = _fresh_run()
        with self.assertRaises(gate.GatePauseRequested):
            await _gate(conn, rid, unattended_behavior="pause").request(_cls())
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_gate -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/gate.py`**

Die Tests legen das Verhalten fest. Zwei Mechaniken, die sie nicht hergeben:

**Das Warten auf den Operator** läuft über ein `Dict[int, asyncio.Future]`, indiziert mit der `approval_id`. `request` legt die Zeile an, erzeugt das Future, und wartet mit `asyncio.wait_for(fut, approval_timeout)`. `answer` setzt das Ergebnis, falls das Future noch offen ist, und liefert `False`, wenn die ID unbekannt oder bereits entschieden ist. Bei `TimeoutError` wird die Zeile mit `decided_by="timeout"` geschlossen und das Future verworfen.

**EV-Berechnung** nach Spec §10.8, mit dem nachgeführten Wert:
```
ev = points * p_success_effektiv - 100 * self.effective_p_detect(classification.p_detect)
```
`p_success_effektiv` ist `clamp_llm_adjustment(classification.p_success, p_success_override)`, sofern ein Override übergeben wurde, sonst der Prior.

`note_detection` schreibt `log_score(action="detection", points=-100, risk_level="high", detected=True)`, erhöht den internen Zähler und liefert `detection_count >= detection_budget`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_gate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/gate.py software/tests/test_agent_gate.py
git commit -m "feat(agent): add approval gate with EV arbiter and detection tracking"
```

---

### Task 5: LLM-Anbieter

**Files:**
- Create: `software/agent/llm/__init__.py`, `software/agent/llm/provider.py`, `software/agent/llm/anthropic_client.py`, `software/agent/llm/openai_client.py`
- Test: `software/tests/test_agent_provider.py`

**Interfaces:**
- Consumes: nichts
- Produces:
  - `ToolSpec` — `NamedTuple` mit `name: str`, `description: str`, `parameters: dict`
  - `ToolCall` — `NamedTuple` mit `id: str`, `name: str`, `arguments: dict`
  - `Completion` — `NamedTuple` mit `text: str`, `tool_calls: List[ToolCall]`, `input_tokens: int`, `output_tokens: int`, `stop_reason: str`
  - `LlmClient` — abstrakte Basis mit `await complete(system: str, messages: List[dict], tools: List[ToolSpec], max_tokens: int, temperature: float) -> Completion`, Attributen `provider: str`, `model: str`, `supports_tools: bool`
  - `provider.create_client(cfg) -> LlmClient` — `cfg` hat `provider`, `api_key`, `model`, `base_url`
  - `provider.capability_tier(model: str, provider_name: str) -> str` — `"full"`, `"reduced"` oder `"minimal"`
  - `provider.TIER_LIMITS: Dict[str, dict]` mit `orchestrator_turns`, `executor_turns`, `truncate_chars`, `max_phase`, `tool_set`
  - `ProviderError` — Exception mit lesbarer Meldung

**Nachrichtenformat:** intern das OpenAI-nahe Format `{"role": "user"|"assistant"|"tool", "content": str, "tool_calls": [...], "tool_call_id": str}`. Die Anthropic-Implementierung übersetzt in Content-Blöcke; die OpenAI-Implementierung gibt es fast unverändert weiter.

- [ ] **Step 1: Write the failing tests**

```python
class TestClientSelection(unittest.TestCase):
    def test_anthropic_provider(self):
        c = provider.create_client(_cfg(provider="anthropic", api_key="k",
                                        model="claude-sonnet-4"))
        self.assertEqual(c.provider, "anthropic")
        self.assertTrue(c.supports_tools)

    def test_openrouter_requires_explicit_model(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="openrouter", api_key="k", model=None))
        self.assertIn("model", str(cm.exception).lower())

    def test_opencode_zen_uses_openai_protocol(self):
        c = provider.create_client(_cfg(provider="opencode", api_key="k",
                                        model="grok-code"))
        self.assertIsInstance(c, openai_client.OpenAiCompatibleClient)

    def test_local_provider_needs_no_api_key(self):
        c = provider.create_client(_cfg(provider="local", api_key=None,
                                        model="qwen2.5:14b",
                                        base_url="http://127.0.0.1:11434/v1"))
        self.assertEqual(c.provider, "local")

    def test_missing_api_key_names_the_provider(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="anthropic", api_key=None,
                                        model="claude-sonnet-4"))
        self.assertIn("anthropic", str(cm.exception).lower())

    def test_unknown_provider_lists_the_supported_ones(self):
        with self.assertRaises(provider.ProviderError) as cm:
            provider.create_client(_cfg(provider="hal9000", api_key="k", model="m"))
        for name in ("anthropic", "openrouter", "opencode", "local"):
            self.assertIn(name, str(cm.exception))

    def test_no_provider_configured_is_a_clean_error(self):
        with self.assertRaises(provider.ProviderError):
            provider.create_client(_cfg(provider=None, api_key=None, model=None))

class TestCapabilityTiers(unittest.TestCase):
    def test_frontier_models_get_full_tier(self):
        for m in ("claude-sonnet-4", "anthropic/claude-sonnet-4", "gpt-4o"):
            self.assertEqual(provider.capability_tier(m, "openrouter"), "full")

    def test_local_models_are_not_full(self):
        self.assertIn(provider.capability_tier("qwen2.5:14b", "local"),
                      ("reduced", "minimal"))

    def test_tier_limits_shrink_monotonically(self):
        full = provider.TIER_LIMITS["full"]
        red = provider.TIER_LIMITS["reduced"]
        mini = provider.TIER_LIMITS["minimal"]
        self.assertGreater(full["orchestrator_turns"], red["orchestrator_turns"])
        self.assertGreater(red["orchestrator_turns"], mini["orchestrator_turns"])
        self.assertGreater(full["truncate_chars"], red["truncate_chars"])
        self.assertGreater(full["max_phase"], red["max_phase"])

    def test_only_full_tier_allows_phase_five(self):
        self.assertGreaterEqual(provider.TIER_LIMITS["full"]["max_phase"], 5)
        self.assertLess(provider.TIER_LIMITS["reduced"]["max_phase"], 5)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_provider -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement the three modules**

`provider.create_client` ist eine Zuordnung von Anbieternamen auf Klasse und Vorbelegung:

| `provider` | Klasse | `base_url`-Vorbelegung | Pflichtfelder |
|---|---|---|---|
| `anthropic` | `AnthropicClient` | SDK-Vorbelegung | `api_key` |
| `openrouter` | `OpenAiCompatibleClient` | `https://openrouter.ai/api/v1` | `api_key`, `model` |
| `opencode` | `OpenAiCompatibleClient` | aus `cfg.base_url`, sonst Fehler mit Hinweis | `api_key`, `model` |
| `local` | `OpenAiCompatibleClient` | `http://127.0.0.1:11434/v1` | `model` |

`TIER_LIMITS` aus Spec §13:
```python
TIER_LIMITS = {
    "full":    {"orchestrator_turns": 20, "executor_turns": 16,
                "truncate_chars": 4000, "max_phase": 5, "tool_set": "all"},
    "reduced": {"orchestrator_turns": 12, "executor_turns": 8,
                "truncate_chars": 2000, "max_phase": 4, "tool_set": "core"},
    "minimal": {"orchestrator_turns": 8,  "executor_turns": 6,
                "truncate_chars": 1000, "max_phase": 3, "tool_set": "bare"},
}
```

`capability_tier` arbeitet über eine Allowlist von Modellfamilien für `"full"` (Claude Sonnet/Opus ab 4, GPT-4o und Nachfolger, Gemini Pro), `"minimal"` für `provider == "local"` mit einer Parameterzahl unter 30B im Namen, sonst `"reduced"`. Überschreibbar per Konfiguration (Task 7).

Beide Clients kapseln ihr SDK und übersetzen in `Completion`. Netzwerkfehler werden als `ProviderError` mit der Anbieter- und Modellangabe erneut geworfen.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_provider -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/llm/ software/tests/test_agent_provider.py
git commit -m "feat(agent): add four-provider LLM abstraction with capability tiers"
```

---

### Task 6: Tool-Calling-Schleife

**Files:**
- Create: `software/agent/llm/loop.py`, `software/agent/llm/mock.py`
- Test: `software/tests/test_agent_loop.py`

**Interfaces:**
- Consumes: `ToolSpec`, `ToolCall`, `Completion`, `LlmClient` (Task 5); `queries.log_llm_interaction` (Task 1)
- Produces:
  - `Tool` — `NamedTuple` mit `spec: ToolSpec`, `fn: Callable[..., Awaitable[Any]]`
  - `await loop.run(client, *, system, prompt, tools: List[Tool], max_turns, max_tokens=4096, temperature=0.3, conn=None, run_id=None, caller_context="", log_level="off", truncate_chars=4000) -> str`
  - `loop.truncate(text: str, limit: int) -> Tuple[str, bool]`
  - `mock.MockClient(responses: List[Completion])` — `LlmClient`-Implementierung, `remaining` zählt die Warteschlange
  - `mock.text(s, *, total_tokens=120)` / `mock.calls(*pairs, total_tokens=120)` — Hilfsfunktionen zum Bauen von `Completion`-Objekten; die Token-Zahl ist setzbar, weil Task 13 das Token-Budget damit prüft

- [ ] **Step 1: Write the failing tests**

```python
class TestTruncation(unittest.TestCase):
    def test_short_output_untouched(self):
        out, trunc = loop.truncate("kurz", 4000)
        self.assertEqual(out, "kurz")
        self.assertFalse(trunc)

    def test_long_output_keeps_head_and_tail(self):
        src = "A" * 3000 + "B" * 3000
        out, trunc = loop.truncate(src, 4000)
        self.assertTrue(trunc)
        self.assertTrue(out.startswith("A" * 2000))
        self.assertTrue(out.endswith("B" * 2000))
        self.assertIn("OUTPUT TRUNCATED", out)

    def test_truncation_counts_characters_not_bytes(self):
        """Nicht-ASCII darf nicht mitten in ein Zeichen schneiden."""
        src = "ü" * 3000
        out, trunc = loop.truncate(src, 4000)
        self.assertTrue(trunc)
        self.assertEqual(out.count("ü"), 4000)

class TestBasicLoop(IsolatedAsyncioTestCase):
    async def test_text_only_response_returns_immediately(self):
        c = mock.MockClient([mock.text("fertig")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "fertig")
        self.assertEqual(c.remaining, 0)

    async def test_tool_call_then_text(self):
        seen = []
        async def echo(value):
            seen.append(value)
            return {"echoed": value}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient([mock.calls(("echo", {"value": "hi"})), mock.text("ok")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "ok")
        self.assertEqual(seen, ["hi"])

    async def test_parallel_tool_calls_in_one_turn_all_execute(self):
        seen = []
        async def note(n):
            seen.append(n)
            return {"ok": n}
        t = _tool("note", note, {"n": "string"})
        c = mock.MockClient([
            mock.calls(("note", {"n": "a"}), ("note", {"n": "b"})),
            mock.text("done")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=8)
        self.assertEqual(sorted(seen), ["a", "b"])

class TestBrokenToolCalling(IsolatedAsyncioTestCase):
    """Review Focus 4: die Schleife muss weiterlaufen und lesbar antworten."""
    async def test_unknown_tool_name_returns_error_and_continues(self):
        c = mock.MockClient([mock.calls(("nope", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "weiter")

    async def test_unknown_tool_error_names_the_available_tools(self):
        captured = {}
        async def ok():
            return {}
        t = _tool("real_tool", ok, {})
        c = _capturing_mock(captured, [mock.calls(("nope", {})), mock.text("x")])
        await loop.run(c, system="s", prompt="p", tools=[t], max_turns=8)
        self.assertIn("real_tool", captured["last_tool_result"])

    async def test_missing_required_argument_is_reported_not_raised(self):
        async def needs(value):
            return {"v": value}
        t = _tool("needs", needs, {"value": "string"})
        c = mock.MockClient([mock.calls(("needs", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")

    async def test_tool_raising_is_reported_not_raised(self):
        async def boom():
            raise RuntimeError("kaputt")
        t = _tool("boom", boom, {})
        captured = {}
        c = _capturing_mock(captured, [mock.calls(("boom", {})), mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")
        self.assertIn("kaputt", captured["last_tool_result"])

    async def test_unexpected_extra_argument_is_rejected_cleanly(self):
        async def one(value):
            return {"v": value}
        t = _tool("one", one, {"value": "string"})
        c = mock.MockClient([mock.calls(("one", {"value": "a", "bogus": 1})),
                             mock.text("weiter")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "weiter")

class TestTurnBudget(IsolatedAsyncioTestCase):
    async def test_exhausted_budget_returns_marker_not_exception(self):
        async def spin():
            return {}
        t = _tool("spin", spin, {})
        c = mock.MockClient([mock.calls(("spin", {}))] * 10)
        out = await loop.run(c, system="s", prompt="p", tools=[t], max_turns=3)
        self.assertIn("MAX_TURNS", out)

    async def test_budget_counts_completions_not_tool_calls(self):
        async def spin():
            return {}
        t = _tool("spin", spin, {})
        c = mock.MockClient([mock.calls(("spin", {}), ("spin", {})),
                             mock.text("fertig")])
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=2), "fertig")

class TestTextProtocolFallback(IsolatedAsyncioTestCase):
    async def test_parses_tool_block_from_plain_text(self):
        seen = []
        async def echo(value):
            seen.append(value)
            return {"ok": True}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient(
            [mock.text('TOOL_CALL\n{"name": "echo", "arguments": {"value": "hi"}}\nEND'),
             mock.text("fertig")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "fertig")
        self.assertEqual(seen, ["hi"])

    async def test_malformed_json_in_block_is_reported_and_loop_continues(self):
        async def echo(value):
            return {}
        t = _tool("echo", echo, {"value": "string"})
        c = mock.MockClient([mock.text("TOOL_CALL\n{nicht json}\nEND"),
                             mock.text("fertig")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[t],
                                        max_turns=8), "fertig")

    async def test_text_without_block_is_treated_as_final_answer(self):
        c = mock.MockClient([mock.text("nur prosa")], supports_tools=False)
        self.assertEqual(await loop.run(c, system="s", prompt="p", tools=[],
                                        max_turns=8), "nur prosa")

class TestObservability(IsolatedAsyncioTestCase):
    async def test_each_completion_is_logged_with_tokens(self):
        conn, rid = _fresh_run()
        c = mock.MockClient([mock.text("fertig")])
        await loop.run(c, system="s", prompt="p", tools=[], max_turns=8,
                       conn=conn, run_id=rid, caller_context="orchestrator")
        row = conn.execute("SELECT caller_context, status, total_tokens "
                           "FROM llm_interactions").fetchone()
        self.assertEqual(row["caller_context"], "orchestrator")
        self.assertEqual(row["status"], "success")

    async def test_prompt_text_only_persisted_at_full_level(self):
        conn, rid = _fresh_run()
        await loop.run(mock.MockClient([mock.text("x")]), system="s", prompt="geheim",
                       tools=[], max_turns=8, conn=conn, run_id=rid, log_level="off")
        self.assertIsNone(
            conn.execute("SELECT prompt_text FROM llm_interactions").fetchone()[0])
        await loop.run(mock.MockClient([mock.text("x")]), system="s", prompt="geheim",
                       tools=[], max_turns=8, conn=conn, run_id=rid, log_level="full")
        texts = [r[0] for r in conn.execute("SELECT prompt_text FROM llm_interactions")]
        self.assertIn("geheim", "".join(t or "" for t in texts))

    async def test_provider_error_is_logged_as_error_row(self):
        conn, rid = _fresh_run()
        with self.assertRaises(provider.ProviderError):
            await loop.run(mock.FailingClient("kein Kontakt"), system="s", prompt="p",
                           tools=[], max_turns=8, conn=conn, run_id=rid)
        row = conn.execute("SELECT status, error_message FROM llm_interactions").fetchone()
        self.assertEqual(row["status"], "error")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_loop -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/llm/mock.py`**

`MockClient` nimmt eine Liste von `Completion`-Objekten und gibt bei jedem `complete`-Aufruf das nächste zurück. Ist die Warteschlange leer, wird eine `AssertionError` mit dem Hinweis geworfen, dass Antworten fehlen — ein stiller Fehlschlag wäre in den Orchestrator-Tests nicht auffindbar. `supports_tools` ist ein Konstruktor-Argument. `FailingClient` wirft `ProviderError`. Die Helfer `text()` und `calls()` bauen `Completion`-Objekte mit plausiblen Token-Zahlen.

- [ ] **Step 4: Implement `software/agent/llm/loop.py`**

Die Schleife: `messages` mit der Nutzernachricht beginnen, dann bis `max_turns` mal `client.complete` rufen. Liefert die Antwort keine Tool-Aufrufe, ist ihr Text das Ergebnis. Sonst alle Aufrufe des Turns **gleichzeitig** über `asyncio.gather(..., return_exceptions=True)` ausführen, jedes Ergebnis als `{"role": "tool", "tool_call_id": …, "content": json.dumps(...)}` anhängen, nächster Turn. Nach Erschöpfung des Budgets wird `"[MAX_TURNS reached after N turns]"` plus der letzte Text zurückgegeben.

**Jeder Tool-Fehler wird zum Tool-Ergebnis**, nie zur Exception (Review Focus 4). Vier Fälle: unbekannter Name → `{"error": "unknown tool 'x'", "available": [...]}`; fehlendes Pflichtargument oder unerwartetes Extra-Argument → `inspect.signature(...).bind(**arguments)` schlägt fehl, Meldung als `{"error": …}`; Exception im Tool → `{"error": "<Typ>: <Nachricht>"}`. Tool-Ergebnisse werden vor dem Anhängen durch `truncate` geschickt.

**Kürzung** nach Spec: über `limit` Zeichen wird `text[:limit//2]`, die Markierung und `text[-(limit//2):]` zusammengesetzt. Zeichen-Slicing, keine Bytes.

**Text-Protokoll-Fallback** greift, wenn `client.supports_tools` falsch ist. Der System-Prompt bekommt eine Anleitung angehängt, Tool-Aufrufe zwischen `TOOL_CALL` und `END` als JSON-Objekt mit `name` und `arguments` zu schreiben. Der Parser sucht diese Blöcke per Regex; fehlerhaftes JSON wird als Tool-Ergebnis mit Fehlermeldung zurückgegeben, statt den Lauf abzubrechen. Text ohne Block ist die Endantwort.

**Protokollierung:** vor jedem `complete` den Startzeitpunkt nehmen, danach `log_llm_interaction` mit Anbieter, Modell, `caller_context`, Token-Zahlen und Latenz schreiben. Prompt- und Antworttext nur bei `log_level == "full"`. Eine `ProviderError` wird als `status="error"`-Zeile geschrieben und dann weitergeworfen — der Aufrufer entscheidet.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_loop -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/agent/llm/loop.py software/agent/llm/mock.py software/tests/test_agent_loop.py
git commit -m "feat(agent): add tool-calling loop with text-protocol fallback"
```

---

### Task 7: Konfiguration

**Files:**
- Create: `software/agent/config.py`
- Modify: `configs/raccoon.yaml` (neuer `agent:`-Block, Sliver-Hinweis)
- Test: `software/tests/test_agent_config.py`

**Interfaces:**
- Consumes: `provider.capability_tier`, `provider.TIER_LIMITS` (Task 5)
- Produces:
  - `AgentConfig` — Dataclass mit `provider`, `api_key`, `model`, `base_url`, `capability_tier`, `llm_log_level`, `db_path`, `c2_url`, `c2_token`, `c2_verify_tls`, `bind_host`, `bind_port`, `agent_token`, `max_concurrent_executors`, `approval_timeout`
  - `CampaignConfig` — Dataclass mit `beacons: List[str]`, `scope_allow`, `scope_deny`, `phases: Set[int]`, `risk_profile`, `ev_threshold`, `p_detect_prior`, `detection_budget`, `unattended_behavior`, `max_runtime_seconds`, `max_tokens_total`, `campaign_interval`, `restore_interval`, `mode`
  - `config.load(argv=None, yaml_path=None, env=None) -> AgentConfig`
  - `config.RISK_PROFILES: Dict[str, dict]`
  - `CampaignConfig.from_form(payload: dict, *, tier: str) -> CampaignConfig` — wendet Profil und Stufen-Obergrenze an
  - `config.available() -> Tuple[bool, str]` — `(verfügbar, grund)` für `/api/ai/status`

- [ ] **Step 1: Write the failing tests**

```python
class TestResolutionCascade(unittest.TestCase):
    def test_yaml_beats_env(self):
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
            "provider": "anthropic", "model": "claude-sonnet-4"}}}),
            env={"AGENT_PROVIDER": "openrouter"})
        self.assertEqual(cfg.provider, "anthropic")

    def test_cli_beats_yaml(self):
        cfg = config.load(argv=["--provider", "local", "--model", "qwen2.5:14b"],
                          yaml_path=_yaml({"agent": {"llm": {"provider": "anthropic"}}}),
                          env={})
        self.assertEqual(cfg.provider, "local")

    def test_env_used_when_yaml_silent(self):
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {}}),
                          env={"AGENT_PROVIDER": "openrouter", "AGENT_MODEL": "m",
                               "AGENT_API_KEY": "k"})
        self.assertEqual(cfg.provider, "openrouter")

    def test_missing_file_yields_defaults_without_raising(self):
        cfg = config.load(argv=[], yaml_path="/nonexistent/x.yaml", env={})
        self.assertIsNone(cfg.provider)

    def test_malformed_yaml_warns_and_falls_back(self):
        cfg = config.load(argv=[], yaml_path=_raw_yaml("agent: [unclosed"), env={})
        self.assertIsNone(cfg.provider)

    def test_api_key_never_read_from_yaml_body(self):
        """Spec: Keys nur aus Env oder 0600-Datei."""
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
            "provider": "anthropic", "api_key": "IM-REPO"}}}), env={})
        self.assertNotEqual(cfg.api_key, "IM-REPO")

    def test_api_key_from_keyfile(self):
        path = _keyfile("sk-geheim", mode=0o600)
        cfg = config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
            "provider": "anthropic", "api_key_file": path}}}), env={})
        self.assertEqual(cfg.api_key, "sk-geheim")

    def test_world_readable_keyfile_is_refused(self):
        path = _keyfile("sk-geheim", mode=0o644)
        with self.assertRaises(config.ConfigError):
            config.load(argv=[], yaml_path=_yaml({"agent": {"llm": {
                "api_key_file": path}}}), env={})

class TestAvailability(unittest.TestCase):
    def test_unavailable_without_provider(self):
        ok, reason = config.load(argv=[], yaml_path=None, env={}).available()
        self.assertFalse(ok)
        self.assertIn("provider", reason.lower())

    def test_available_with_provider_and_key(self):
        ok, _ = config.load(argv=[], yaml_path=None,
                            env={"AGENT_PROVIDER": "anthropic",
                                 "AGENT_MODEL": "claude-sonnet-4",
                                 "AGENT_API_KEY": "k"}).available()
        self.assertTrue(ok)

class TestRiskProfiles(unittest.TestCase):
    def test_normal_profile_matches_spec(self):
        p = config.RISK_PROFILES["normal"]
        self.assertEqual(p["ev_threshold"], 0.0)
        self.assertAlmostEqual(p["p_detect_prior"], 0.15)
        self.assertEqual(p["detection_budget"], 3)

    def test_passive_is_stricter_and_aggressive_looser(self):
        pas, nor, agg = (config.RISK_PROFILES[k]
                         for k in ("passive", "normal", "aggressive"))
        self.assertGreater(pas["ev_threshold"], nor["ev_threshold"])
        self.assertLess(agg["ev_threshold"], nor["ev_threshold"])
        self.assertLessEqual(pas["detection_budget"], nor["detection_budget"])

    def test_explicit_values_override_the_profile(self):
        c = config.CampaignConfig.from_form(
            {"risk_profile": "normal", "ev_threshold": 25.0,
             "scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}, tier="full")
        self.assertEqual(c.ev_threshold, 25.0)

class TestCampaignForm(unittest.TestCase):
    def test_phase_five_off_by_default(self):
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}, tier="full")
        self.assertNotIn(5, c.phases)

    def test_tier_caps_requested_phases(self):
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"],
             "phases": [1, 2, 3, 4, 5]}, tier="reduced")
        self.assertNotIn(5, c.phases)
        self.assertIn(4, c.phases)

    def test_empty_scope_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form({"beacons": ["a"]}, tier="full")

    def test_no_beacons_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.CampaignConfig.from_form(
                {"scope_allow": ["10.0.1.0/24"], "beacons": []}, tier="full")

    def test_defaults_match_the_form_in_the_spec(self):
        c = config.CampaignConfig.from_form(
            {"scope_allow": ["10.0.1.0/24"], "beacons": ["a"]}, tier="full")
        self.assertEqual(c.max_runtime_seconds, 7200)
        self.assertEqual(c.max_tokens_total, 500_000)
        self.assertEqual(c.campaign_interval, 15)
        self.assertEqual(c.unattended_behavior, "decide")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_config -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/config.py`**

Kaskade CLI > YAML > Env > Vorbelegung, je Feld einzeln aufgelöst. `argparse` für die CLI-Ebene. Fehlende oder fehlerhafte YAML gibt eine Warnung auf stderr und die Vorbelegungen zurück, ohne zu werfen.

`api_key` wird **nie** aus dem YAML-Rumpf gelesen — nur aus `AGENT_API_KEY` oder der in `api_key_file` benannten Datei, und diese muss Modus `0600` haben, sonst `ConfigError`.

`RISK_PROFILES` (Spec §17.2, `normal` ist dort festgelegt; die anderen zwei sind meine Ableitung und müssen die Monotonie der Tests erfüllen):
```python
RISK_PROFILES = {
    "passive":    {"ev_threshold": 25.0, "p_detect_prior": 0.30, "detection_budget": 1},
    "normal":     {"ev_threshold":  0.0, "p_detect_prior": 0.15, "detection_budget": 3},
    "aggressive": {"ev_threshold": -25.0, "p_detect_prior": 0.10, "detection_budget": 6},
}
```

`from_form` nimmt das Profil als Basis, überschreibt mit explizit gesetzten Feldern, setzt `phases` auf `{1,2,3,4}` falls nicht angegeben, und schneidet anschließend alles über `TIER_LIMITS[tier]["max_phase"]` ab. Leerer Scope oder leere Beacon-Liste sind `ConfigError`.

- [ ] **Step 4: Add the `agent:` block to `configs/raccoon.yaml`**

Neuer Block am Ende, mit Kommentaren im Stil der Datei. Enthält `enabled`, `llm` (`provider`, `model`, `base_url`, `api_key_file`, `llm_log_level`), `service` (`bind_host: "127.0.0.1"`, `bind_port: 8099`), `c2` (`url`, `verify_tls: false`), `limits` (`max_concurrent_executors: 4`, `approval_timeout`), und `defaults` mit den Kampagnen-Vorbelegungen. Vorbelegung `enabled: false`.

Dazu der Hinweis über `c2.sliver` (Spec §5.2), dass `sliver.enabled: true` und Agenten-Betrieb sich ausschließen, weil eine Sliver-verwaltete Box beim Team-Server nie eincheckt.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_config -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/agent/config.py configs/raccoon.yaml software/tests/test_agent_config.py
git commit -m "feat(agent): add configuration cascade and risk profiles"
```

---

### Task 8: C2-Client

**Files:**
- Create: `software/agent/c2client.py`
- Test: `software/tests/test_agent_c2client.py`

**Interfaces:**
- Consumes: `AgentConfig` (Task 7)
- Produces:
  - `C2Client(base_url, token, *, verify_tls=False, session=None)`
  - `await list_agents() -> List[dict]`
  - `await get_agent(agent_id) -> Optional[dict]`
  - `await queue_task(agent_id, cmd, args="", data="", timeout=300, lane="agent") -> str` — liefert die Task-ID
  - `await get_task_result(task_id) -> Optional[dict]` — `None` solange `status == "pending"`
  - `await await_task(task_id, *, timeout, poll_interval=2.0, is_alive=None) -> dict` — pollt bis Ergebnis
  - `await exec_server_tool(argv: List[str], *, tool, timeout) -> str` — liefert die `run_id`
  - `await get_server_tool_result(run_id) -> Optional[dict]`
  - `await await_server_tool(run_id, *, timeout, poll_interval=2.0) -> dict`
  - `await set_beacon_interval(agent_id, seconds, jitter) -> None`
  - `C2Unavailable`, `C2Unauthorized`, `BeaconGone` — Exceptions

- [ ] **Step 1: Write the failing tests**

```python
class TestTasking(IsolatedAsyncioTestCase):
    async def test_queue_task_sends_agent_lane(self):
        fake = FakeC2()
        c = c2client.C2Client("http://c2", "tok", session=fake)
        await c.queue_task("raccoon-fox", "netscan", "10.0.1.0/24")
        self.assertEqual(fake.last_json["lane"], "agent")

    async def test_queue_task_returns_task_id(self):
        fake = FakeC2(post_response={"id": "ab12cd34"})
        c = c2client.C2Client("http://c2", "tok", session=fake)
        self.assertEqual(await c.queue_task("raccoon-fox", "whoami"), "ab12cd34")

    async def test_bearer_token_is_sent(self):
        fake = FakeC2()
        await c2client.C2Client("http://c2", "tok", session=fake).list_agents()
        self.assertEqual(fake.last_headers["Authorization"], "Bearer tok")

    async def test_pending_result_is_none(self):
        fake = FakeC2(get_response={"status": "pending"})
        c = c2client.C2Client("http://c2", "tok", session=fake)
        self.assertIsNone(await c.get_task_result("ab12cd34"))

    async def test_await_task_polls_until_done(self):
        fake = FakeC2(get_sequence=[{"status": "pending"}, {"status": "pending"},
                                    {"status": "ok", "output": "root"}])
        c = c2client.C2Client("http://c2", "tok", session=fake)
        res = await c.await_task("ab12cd34", timeout=10, poll_interval=0.01)
        self.assertEqual(res["output"], "root")

    async def test_await_task_times_out_with_marker(self):
        fake = FakeC2(get_response={"status": "pending"})
        c = c2client.C2Client("http://c2", "tok", session=fake)
        res = await c.await_task("ab12cd34", timeout=0.05, poll_interval=0.01)
        self.assertFalse(res["success"])
        self.assertIn("timeout", res["output"].lower())

class TestBeaconGoneOffline(IsolatedAsyncioTestCase):
    """Review Focus 3: kein Endlos-Poll auf einem toten Beacon."""
    async def test_await_task_aborts_when_liveness_check_fails(self):
        fake = FakeC2(get_response={"status": "pending"})
        c = c2client.C2Client("http://c2", "tok", session=fake)
        calls = {"n": 0}
        async def is_alive():
            calls["n"] += 1
            return calls["n"] < 3
        with self.assertRaises(c2client.BeaconGone):
            await c.await_task("ab12cd34", timeout=30, poll_interval=0.01,
                               is_alive=is_alive)

class TestServerTools(IsolatedAsyncioTestCase):
    async def test_exec_sends_argv_not_cmd_string(self):
        fake = FakeC2(post_response={"run_id": "r1"})
        c = c2client.C2Client("http://c2", "tok", session=fake)
        await c.exec_server_tool(["nmap", "-sV", "10.0.1.5"], tool="nmap", timeout=900)
        self.assertIn("argv", fake.last_json)
        self.assertNotIn("cmd", fake.last_json)

    async def test_string_command_is_refused_by_type(self):
        c = c2client.C2Client("http://c2", "tok", session=FakeC2())
        with self.assertRaises(TypeError):
            await c.exec_server_tool("nmap -sV 10.0.1.5", tool="nmap", timeout=900)

class TestFailureModes(IsolatedAsyncioTestCase):
    async def test_connection_refused_raises_c2_unavailable(self):
        c = c2client.C2Client("http://c2", "tok", session=FakeC2(raise_connect=True))
        with self.assertRaises(c2client.C2Unavailable):
            await c.list_agents()

    async def test_401_raises_unauthorized(self):
        c = c2client.C2Client("http://c2", "tok", session=FakeC2(status=401))
        with self.assertRaises(c2client.C2Unauthorized):
            await c.list_agents()

    async def test_unknown_agent_returns_none(self):
        c = c2client.C2Client("http://c2", "tok", session=FakeC2(status=404))
        self.assertIsNone(await c.get_agent("nope"))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_c2client -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/c2client.py`**

`aiohttp.ClientSession` mit `Authorization`-Header; die Session ist injizierbar, damit die Tests ohne Netz laufen. `verify_tls=False` setzt `ssl=False` im Connector (Spec §18: selbstsigniertes C2-Zertifikat).

`exec_server_tool` nimmt `List[str]` und wirft `TypeError` bei einem String — die Spec verbietet dem Agenten die String-Form, und ein Typfehler beim Aufruf ist die billigste Durchsetzung.

`await_task` pollt bis Ergebnis oder `timeout`. Bei Timeout wird **kein** Fehler geworfen, sondern ein Ergebnis-Dict mit `success=False` und einer Timeout-Meldung geliefert — das LLM soll es lesen können. Ist `is_alive` gesetzt, wird es bei jedem Poll gerufen; drei aufeinanderfolgende negative Antworten lösen `BeaconGone` aus, damit ein Executor nicht auf einem toten Beacon das Semaphor hält (Review Focus 3).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_c2client -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/c2client.py software/tests/test_agent_c2client.py
git commit -m "feat(agent): add typed Raccoon C2 API client"
```

---

### Task 9: C2-Server — Lanes, Batching, Tool-Läufe, argv, Proxy

**Files:**
- Modify: `software/c2/server.py`
  - `api_create_task` — `server.py:327-353`
  - `server_exec_state` → `tool_runs` — `server.py:481`
  - `_run_server_cmd` — `server.py:483-503`
  - `api_server_exec` / `api_server_exec_result` — `server.py:505-523`
  - `_handle_beacon` — `server.py:1832-1867`, Queue-Auswahl bei `1855-1857`
  - `_handle_register` — `server.py:1753-1806` (Capability-Aufnahme)
  - neue Proxy-Routen innerhalb von `create_app` — `server.py:257-1746`
- Test: `software/tests/test_c2_agent_support.py`

**Interfaces:**
- Consumes: nichts aus `software/agent/` — **harte Regel**, die Kopplung läuft nur über HTTP
- Produces (für Task 8 und Task 15):
  - `POST /api/agents/<id>/task` akzeptiert zusätzlich `lane`
  - `POST /api/server/exec` akzeptiert `{"argv": [...], "tool": str, "timeout": int}` und liefert `{"status":"started","run_id":str,"tool":str}`
  - `GET /api/server/exec/result/<run_id>` → `{"status","output","tool","origin","truncated"}`
  - `GET /api/server/exec/result` → jüngster Lauf mit `origin == "operator"`
  - `GET|POST /api/ai/<path:p>` → Weiterleitung an `AGENT_URL`, `503` wenn nicht erreichbar
  - `_handle_beacon` liefert `{"tasks":[…]}` für Beacons mit `batch`, sonst ein einzelnes Task-Dict

- [ ] **Step 1: Write the failing tests**

```python
class TestTaskLanes(ServerTestBase):
    def test_lane_defaults_to_operator(self):
        _reset_server_state()
        self._register_agent()
        t = self._operator_post("/api/agents/raccoon-a/task", {"cmd": "whoami"})
        self.assertEqual(t["lane"], "operator")

    def test_operator_task_wins_over_older_agent_task(self):
        _reset_server_state()
        self._register_agent()
        self._operator_post("/api/agents/raccoon-a/task",
                            {"cmd": "agent_first", "lane": "agent"})
        self._operator_post("/api/agents/raccoon-a/task",
                            {"cmd": "operator_second", "lane": "operator"})
        self.assertEqual(self._checkin("raccoon-a")["cmd"], "operator_second")

    def test_agent_tasks_served_fifo_once_operator_queue_is_empty(self):
        _reset_server_state()
        self._register_agent()
        for n in ("a1", "a2"):
            self._operator_post("/api/agents/raccoon-a/task",
                                {"cmd": n, "lane": "agent"})
        self.assertEqual(self._checkin("raccoon-a")["cmd"], "a1")
        self.assertEqual(self._checkin("raccoon-a")["cmd"], "a2")

    def test_operator_only_queue_behaves_exactly_as_before(self):
        """Status quo: identische Reihenfolge wie das heutige queue.pop(0)."""
        _reset_server_state()
        self._register_agent()
        for n in ("c1", "c2", "c3"):
            self._operator_post("/api/agents/raccoon-a/task", {"cmd": n})
        self.assertEqual([self._checkin("raccoon-a")["cmd"] for _ in range(3)],
                         ["c1", "c2", "c3"])

class TestBatching(ServerTestBase):
    def test_beacon_without_caps_gets_single_task_dict(self):
        _reset_server_state()
        self._register_agent(caps=None)
        for n in ("t1", "t2"):
            self._operator_post("/api/agents/raccoon-a/task",
                                {"cmd": n, "lane": "agent"})
        resp = self._checkin("raccoon-a")
        self.assertNotIn("tasks", resp)
        self.assertEqual(resp["cmd"], "t1")

    def test_beacon_with_batch_cap_gets_task_list(self):
        _reset_server_state()
        self._register_agent(caps=["batch"])
        for n in ("t1", "t2", "t3"):
            self._operator_post("/api/agents/raccoon-a/task",
                                {"cmd": n, "lane": "agent"})
        resp = self._checkin("raccoon-a")
        self.assertEqual([t["cmd"] for t in resp["tasks"]], ["t1", "t2", "t3"])

    def test_batch_respects_the_cap_limit(self):
        _reset_server_state()
        self._register_agent(caps=["batch"])
        for i in range(12):
            self._operator_post("/api/agents/raccoon-a/task",
                                {"cmd": f"t{i}", "lane": "agent"})
        self.assertLessEqual(len(self._checkin("raccoon-a")["tasks"]), 8)

    def test_batch_puts_operator_tasks_first(self):
        _reset_server_state()
        self._register_agent(caps=["batch"])
        self._operator_post("/api/agents/raccoon-a/task",
                            {"cmd": "ag", "lane": "agent"})
        self._operator_post("/api/agents/raccoon-a/task",
                            {"cmd": "op", "lane": "operator"})
        self.assertEqual(self._checkin("raccoon-a")["tasks"][0]["cmd"], "op")

    def test_empty_queue_still_returns_empty_dict(self):
        _reset_server_state()
        self._register_agent(caps=["batch"])
        self.assertEqual(self._checkin("raccoon-a"), {})

class TestCapabilityStorage(ServerTestBase):
    def test_caps_are_stored_on_the_agent_record(self):
        _reset_server_state()
        self._register_agent(caps=["batch", "sniffer"])
        a = self._operator_get("/api/agents/raccoon-a")
        self.assertEqual(sorted(a["caps"]), ["batch", "sniffer"])

    def test_registration_without_caps_still_succeeds(self):
        """Status quo: alter Beacon gegen neuen Server."""
        _reset_server_state()
        self._register_agent(caps=None)
        self.assertEqual(self._operator_get("/api/agents/raccoon-a")["caps"], [])

class TestToolRuns(ServerTestBase):
    def test_exec_returns_a_run_id(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "hallo"], "tool": "echo"})
        self.assertIn("run_id", r)

    def test_parallel_runs_do_not_overwrite_each_other(self):
        a = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "aaa"], "tool": "echo"})["run_id"]
        b = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "bbb"], "tool": "echo"})["run_id"]
        self._wait_tool(a); self._wait_tool(b)
        self.assertIn("aaa", self._operator_get(f"/api/server/exec/result/{a}")["output"])
        self.assertIn("bbb", self._operator_get(f"/api/server/exec/result/{b}")["output"])

    def test_legacy_endpoint_returns_latest_operator_run_only(self):
        ag = self._operator_post("/api/server/exec",
                                 {"argv": ["echo", "agentrun"], "tool": "nmap",
                                  "origin": "agent"})["run_id"]
        op = self._operator_post("/api/server/exec",
                                 {"cmd": "echo operatorrun", "tool": "custom"})["run_id"]
        self._wait_tool(ag); self._wait_tool(op)
        self.assertIn("operatorrun", self._operator_get("/api/server/exec/result")["output"])

    def test_string_cmd_form_still_works(self):
        """Status quo: das bestehende GUI postet cmd-Strings."""
        r = self._operator_post("/api/server/exec",
                                {"cmd": "echo via-shell", "tool": "custom"})
        self._wait_tool(r["run_id"])
        self.assertIn("via-shell",
                      self._operator_get(f"/api/server/exec/result/{r['run_id']}")["output"])

    def test_argv_form_does_not_interpret_shell_syntax(self):
        r = self._operator_post("/api/server/exec",
                                {"argv": ["echo", "a; whoami"], "tool": "echo"})
        self._wait_tool(r["run_id"])
        out = self._operator_get(f"/api/server/exec/result/{r['run_id']}")["output"]
        self.assertIn("a; whoami", out)

    def test_timeout_keeps_partial_output(self):
        r = self._operator_post(
            "/api/server/exec",
            {"argv": ["sh", "-c", "echo teil; sleep 5"], "tool": "custom",
             "timeout": 1})
        self._wait_tool(r["run_id"], timeout=10)
        res = self._operator_get(f"/api/server/exec/result/{r['run_id']}")
        self.assertIn("teil", res["output"])
        self.assertIn("timeout", res["output"].lower())

    def test_missing_command_is_a_400(self):
        resp = self._operator_post_raw("/api/server/exec", {"tool": "x"})
        self.assertEqual(resp.status_code, 400)

class TestAiProxy(ServerTestBase):
    def test_returns_503_without_agent_service(self):
        resp = self._operator_get_raw("/api/ai/status")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("unavailable", resp.get_json()["error"])

    def test_proxy_requires_operator_auth(self):
        resp = self.client.get("/api/ai/status")
        self.assertEqual(resp.status_code, 401)

    def test_forwards_to_configured_agent_url(self):
        with _stub_agent({"available": True}) as url:
            app = srv.create_app(self.crypto, TEST_TOKEN, self.data_dir,
                                 server_config={"agent_url": url})
            resp = app.test_client().get(
                "/api/ai/status", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
            self.assertTrue(resp.get_json()["available"])

    def test_does_not_import_the_agent_package(self):
        """Harte Regel aus Spec §19.5."""
        src = Path(srv.__file__).read_text()
        self.assertNotIn("software.agent", src)
        self.assertNotIn("from .agent", src)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_c2_agent_support -v`
Expected: FAIL — `lane` fehlt im Task-Dict, `/api/ai/*` liefert 404

- [ ] **Step 3: Add lanes to `api_create_task` (`server.py:327-353`)**

`lane = body.get("lane", "operator")`, abgelehnt mit `400` wenn nicht in `("operator", "agent")`. Feld ins Task-Dict und in den History-Eintrag. Der `_log_event`-Aufruf nennt die Lane mit, damit Agent-Aktionen im Server-Log unterscheidbar sind.

- [ ] **Step 4: Rewrite the queue selection in `_handle_beacon` (`server.py:1855-1857`)**

Statt `queue.pop(0)` eine Auswahl, die Operator-Tasks bevorzugt. `BATCH_MAX = 8`. Bei einem Beacon mit `"batch"` in `caps` werden bis zu `BATCH_MAX` Tasks entnommen — zuerst alle Operator-Tasks in Reihenfolge, dann Agent-Tasks — und als `{"tasks": [...]}` verpackt. Ohne die Capability wird genau ein Task entnommen, Operator zuerst, und wie bisher direkt verpackt. Leere Queue bleibt `{}`.

`_log_event("DISPATCH", …)` schreibt eine Zeile je Task, damit die bestehende Log-Ansicht vollständig bleibt.

- [ ] **Step 5: Store capabilities in `_handle_register` (`server.py:1753-1806`)**

`agents[agent_id]["caps"] = payload.get("caps") or []`. Unbekannte Felder im Payload werden wie bisher ignoriert, damit ein neuer Beacon gegen einen alten Server funktioniert.

- [ ] **Step 6: Replace `server_exec_state` with `tool_runs` (`server.py:481-523`)**

`tool_runs: dict[str, dict]` als Closure-Variable, Einträge `{"status","output","tool","origin","started","truncated"}`. `_run_server_cmd` bekommt die `run_id` und schreibt dorthin. Ein Eintragslimit (die 50 jüngsten) verhindert unbegrenztes Wachstum.

`api_server_exec` akzeptiert `argv` **oder** `cmd`, nicht beides; `origin` kommt aus dem Body mit Vorbelegung `"operator"`. `timeout` aus dem Body, Vorbelegung 300. Rückgabe enthält die `run_id`.

`_run_server_cmd` verzweigt: bei `argv` über `subprocess.Popen(argv, ...)` ohne Shell, bei `cmd` wie heute mit `shell=True`. In beiden Fällen wird mit `communicate(timeout=…)` gearbeitet; bei `TimeoutExpired` wird das Kind terminiert (`kill()` nach `terminate()`), die bis dahin gelesene Ausgabe behalten und `f"\n[timeout after {n}s, partial output]"` angehängt. Der neue Result-Endpoint mit `run_id` und der alte ohne werden beide registriert; der alte filtert auf `origin == "operator"` und liefert den jüngsten.

- [ ] **Step 7: Add the proxy routes inside `create_app`**

`agent_url` kommt aus `server_config.get("agent_url")` oder `os.environ.get("AGENT_URL")`. Die Route `@app.route("/api/ai/<path:p>", methods=["GET","POST"])` mit `@require_auth` leitet per `urllib.request` weiter — Methode, Body und `Content-Type` durchreichen, Antwort-Status und -Body zurückgeben. `URLError`, `ConnectionError` und ein fehlendes `agent_url` ergeben `503 {"error": "agent service unavailable", "detail": …}`. Timeout 30 s. Zusätzlich wird der Header `X-Agent-Token` aus `RACCOON_AGENT_TOKEN` gesetzt (Spec §18).

**Kein Import aus `software/agent/`** — `urllib` reicht und ist Standardbibliothek.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_c2_agent_support -v`
Expected: PASS

- [ ] **Step 9: Verify the existing suite is untouched**

Run: `python -m unittest software.tests.test_c2_server software.tests.test_beacon -v`
Expected: PASS, unverändert zum Stand vor diesem Task

- [ ] **Step 10: Commit**

```bash
git add software/c2/server.py software/tests/test_c2_agent_support.py
git commit -m "feat(c2): add task lanes, batching, isolated tool runs and the AI proxy"
```

---

### Task 10: Beacon — Capabilities und Batch-Verarbeitung

**Files:**
- Modify: `software/c2/beacon.py`
  - `_system_info` — `beacon.py:1439-1465` (Capability-Meldung)
  - `_beacon_loop` — `beacon.py:3978-4032` (Batch-Verzweigung vor `_process_tasking`)
- Modify: `software/c2/beacon_standalone.py` (dieselbe Capability-Meldung)
- Test: `software/tests/test_beacon_caps.py`

**Interfaces:**
- Consumes: `{"tasks": [...]}` aus Task 9
- Produces: `caps`-Feld im Register- und Beacon-Payload
  - `Beacon._detect_caps() -> List[str]`
  - `Beacon._process_tasking_batch(tasking: dict) -> None`

- [ ] **Step 1: Write the failing tests**

```python
class TestCapabilityDetection(unittest.TestCase):
    def test_batch_is_always_advertised(self):
        self.assertIn("batch", _beacon()._detect_caps())

    def test_platform_class_is_advertised(self):
        caps = _beacon()._detect_caps()
        self.assertTrue(("posix" in caps) ^ ("windows" in caps))

    def test_smbloot_is_advertised(self):
        self.assertIn("smbloot", _beacon()._detect_caps())

    def test_sniffer_requires_an_existing_capture_dir_with_pcaps(self):
        b = _beacon()
        with _tmp_capture_dir(files=[]) as d:
            b.capture_dir = d
            self.assertNotIn("sniffer", b._detect_caps())
        with _tmp_capture_dir(files=["cap_001.pcap"]) as d:
            b.capture_dir = d
            self.assertIn("sniffer", b._detect_caps())

    def test_wifi_scan_requires_a_wireless_interface(self):
        b = _beacon()
        with _fake_sysfs(interfaces={"eth0": {}}):
            self.assertNotIn("wifi:scan", b._detect_caps())
        with _fake_sysfs(interfaces={"wlan0": {"wireless": True}}):
            self.assertIn("wifi:scan", b._detect_caps())

    def test_wifi_monitor_requires_a_known_driver(self):
        b = _beacon()
        with _fake_sysfs(interfaces={"wlan0": {"wireless": True,
                                               "driver": "brcmfmac"}}):
            caps = b._detect_caps()
            self.assertIn("wifi:scan", caps)
            self.assertNotIn("wifi:monitor", caps)
        with _fake_sysfs(interfaces={"wlan1": {"wireless": True,
                                               "driver": "88XXau"}}):
            self.assertIn("wifi:monitor", b._detect_caps())

    def test_detection_never_raises_on_a_bare_system(self):
        with _fake_sysfs(interfaces=None):
            self.assertIsInstance(_beacon()._detect_caps(), list)

class TestCapsInPayload(unittest.TestCase):
    def test_system_info_carries_caps(self):
        self.assertIn("caps", _beacon()._system_info())

    def test_caps_is_a_list_of_strings(self):
        caps = _beacon()._system_info()["caps"]
        self.assertTrue(all(isinstance(c, str) for c in caps))

class TestBatchProcessing(unittest.TestCase):
    def test_single_task_dict_still_processed(self):
        """Status quo: alter Server, einzelnes Task-Dict."""
        b = _beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch({"cmd": "whoami", "args": "", "task_id": "t1"})
        self.assertEqual([t["task_id"] for t in seen], ["t1"])

    def test_task_list_processed_in_order(self):
        b = _beacon()
        batch = {"tasks": [{"cmd": "whoami", "task_id": "t1"},
                           {"cmd": "pwd", "task_id": "t2"},
                           {"cmd": "id", "task_id": "t3"}]}
        with _capture_processed(b) as seen:
            b._process_tasking_batch(batch)
        self.assertEqual([t["task_id"] for t in seen], ["t1", "t2", "t3"])

    def test_one_failing_task_does_not_stop_the_batch(self):
        b = _beacon()
        batch = {"tasks": [{"cmd": "boom", "task_id": "t1"},
                           {"cmd": "whoami", "task_id": "t2"}]}
        with _capture_processed(b, raise_on="boom") as seen:
            b._process_tasking_batch(batch)
        self.assertIn("t2", [t["task_id"] for t in seen])

    def test_kill_in_a_batch_stops_the_remaining_tasks(self):
        b = _beacon()
        batch = {"tasks": [{"cmd": "kill", "task_id": "t1"},
                           {"cmd": "whoami", "task_id": "t2"}]}
        with _capture_processed(b) as seen:
            b._process_tasking_batch(batch)
        self.assertEqual([t["task_id"] for t in seen], ["t1"])
        self.assertFalse(b._running)

    def test_empty_dict_is_a_no_op(self):
        b = _beacon()
        with _capture_processed(b) as seen:
            b._process_tasking_batch({})
        self.assertEqual(seen, [])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_beacon_caps -v`
Expected: FAIL mit `AttributeError: 'Beacon' object has no attribute '_detect_caps'`

- [ ] **Step 3: Implement `Beacon._detect_caps` in `beacon.py`**

Liefert immer `"batch"`, `"smbloot"` und die Plattformklasse. `"sniffer"` wenn `self.capture_dir` existiert und mindestens eine `*.pcap`-Datei enthält. Für WLAN wird `/sys/class/net/*/wireless` auf Existenz geprüft (`wifi:scan`) und der Treiber über den Symlink `/sys/class/net/<if>/device/driver` gelesen; ein Basename in `("88XXau", "rtl8812au", "8812au")` ergibt zusätzlich `"wifi:monitor"`.

Die gesamte Erkennung läuft in einem `try/except Exception`, das eine Teilliste zurückgibt — ein Beacon darf nicht an der Capability-Erkennung scheitern.

- [ ] **Step 4: Add `caps` to `_system_info` (`beacon.py:1439`)**

`"caps": self._detect_caps()` ins Dict. Damit erscheint es automatisch im Register- **und** Beacon-Payload, weil beide `_system_info` nutzen (`beacon.py:1571`, `1841`, `1960`). Die Erkennung wird einmal im Konstruktor berechnet und gecacht, damit nicht bei jedem Check-in das sysfs gelesen wird.

- [ ] **Step 5: Implement `Beacon._process_tasking_batch` and call it from `_beacon_loop`**

Liegt `"tasks"` im Tasking, wird die Liste sequentiell durch `_process_tasking` geschickt; sonst das Dict selbst, einmal. Nach jedem Task wird `self._running` geprüft und bei `False` abgebrochen, damit `kill` in einem Batch die Restliste nicht mehr ausführt. Eine Exception in einem Task wird geloggt und übersprungen — die Restliste läuft weiter.

In `_beacon_loop` (`beacon.py:4022`) wird der Aufruf `self._process_tasking(tasking)` durch `self._process_tasking_batch(tasking)` ersetzt.

- [ ] **Step 6: Mirror the capability advertisement in `beacon_standalone.py`**

Dieselbe `caps`-Meldung, damit ein standalone gestarteter Beacon nicht als capability-los gilt.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_beacon_caps -v`
Expected: PASS

- [ ] **Step 8: Verify backward compatibility in both directions**

Run: `python -m unittest software.tests.test_beacon software.tests.test_c2_server software.tests.test_c2_agent_support -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add software/c2/beacon.py software/c2/beacon_standalone.py software/tests/test_beacon_caps.py
git commit -m "feat(beacon): advertise capabilities and process task batches"
```

---

### Task 11: Executoren und Router

**Files:**
- Create: `software/agent/executor/__init__.py`, `software/agent/executor/beacon.py`, `software/agent/executor/server_tool.py`, `software/agent/executor/router.py`
- Test: `software/tests/test_agent_router.py`

**Interfaces:**
- Consumes: `safety.classify`, `safety.enforce_scan_limits`, `safety.TIER_*` (Task 2); `Scope.check` (Task 3); `Gate.request`, `gate.scan_for_detection`, `Gate.note_detection` (Task 4); `C2Client` (Task 8); `loop.truncate` (Task 6)
- Produces:
  - `ActionResult` — `NamedTuple` mit `success: bool`, `output: str`, `exit_code: int`, `truncated: bool`, `path: str`, `blocked_reason: Optional[str]`
  - `Router(c2, gate, scope, *, conn, run_id, beacon_ids, caps_by_beacon, phase5_enabled, truncate_chars, campaign_tokens)`
  - `await Router.run_command(command: str, *, beacon_id=None, server_side=False, timeout=None, p_success_override=None) -> ActionResult`
  - `Router.target_kind(beacon_id) -> str`
  - `beacon.run_on_beacon(c2, beacon_id, command, *, timeout) -> ActionResult`
  - `server_tool.run_on_server(c2, argv, *, tool, timeout) -> ActionResult`
  - `RouterAborted` — Exception, wenn das Detection-Budget erschöpft ist

- [ ] **Step 1: Write the failing tests**

```python
class TestGating(IsolatedAsyncioTestCase):
    async def test_tier_one_is_blocked_before_any_execution(self):
        r, c2 = _router()
        res = await r.run_command("kill", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIsNotNone(res.blocked_reason)
        self.assertEqual(c2.queued, [])

    async def test_out_of_scope_target_is_blocked_before_execution(self):
        r, c2 = _router()
        res = await r.run_command("nmap -sV 172.16.0.5", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("172.16.0.5", res.blocked_reason)
        self.assertEqual(c2.queued, [])

    async def test_shell_metachars_are_blocked(self):
        r, c2 = _router()
        res = await r.run_command("shell whoami; id", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertEqual(c2.queued, [])

    async def test_tier_two_consults_the_gate(self):
        r, c2 = _router(gate_allows=False)
        res = await r.run_command("lsassy -u a -p b 10.0.1.5", server_side=True)
        self.assertFalse(res.success)
        self.assertIn("gate", res.blocked_reason.lower())

    async def test_approved_tier_two_executes(self):
        r, c2 = _router(gate_allows=True)
        res = await r.run_command("lsassy -u a -p b 10.0.1.5", server_side=True)
        self.assertTrue(res.success)

    async def test_blocked_result_is_a_value_not_an_exception(self):
        r, _ = _router()
        self.assertIsInstance(await r.run_command("kill", beacon_id="raccoon-fox"),
                              router.ActionResult)

class TestScanLimitsApplied(IsolatedAsyncioTestCase):
    async def test_nmap_is_rewritten_before_dispatch(self):
        r, c2 = _router()
        await r.run_command("nmap -T5 -sV 10.0.1.5", server_side=True)
        sent = " ".join(c2.exec_calls[-1]["argv"])
        self.assertIn("-T2", sent)
        self.assertIn("--max-rate 50", sent)
        self.assertNotIn("-T5", sent)

class TestPathSelection(IsolatedAsyncioTestCase):
    async def test_beacon_path_queues_an_agent_lane_task(self):
        r, c2 = _router()
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(c2.queued[-1]["lane"], "agent")

    async def test_server_path_sends_argv(self):
        r, c2 = _router()
        await r.run_command("nmap -sV 10.0.1.5", server_side=True)
        self.assertIsInstance(c2.exec_calls[-1]["argv"], list)

    async def test_dropbox_target_kind_is_detected_from_caps(self):
        r, _ = _router(caps={"raccoon-pi": ["sniffer", "batch"],
                             "raccoon-fox": ["batch"]})
        self.assertEqual(r.target_kind("raccoon-pi"), "dropbox")
        self.assertEqual(r.target_kind("raccoon-fox"), "beacon")

class TestDetection(IsolatedAsyncioTestCase):
    async def test_reset_in_output_is_recorded_as_detection(self):
        r, c2 = _router(beacon_output="connection reset by peer")
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(r.gate.detection_count, 1)

    async def test_clean_output_records_nothing(self):
        r, c2 = _router(beacon_output="445/tcp open microsoft-ds")
        await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertEqual(r.gate.detection_count, 0)

    async def test_budget_exhaustion_aborts_the_campaign(self):
        r, c2 = _router(beacon_output="connection reset by peer",
                        detection_budget=1)
        with self.assertRaises(router.RouterAborted):
            await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")

class TestBeaconGoesOffline(IsolatedAsyncioTestCase):
    """Review Focus 3: kein hängender Executor auf einem toten Beacon."""
    async def test_dead_beacon_returns_a_failed_result_not_a_hang(self):
        r, c2 = _router(beacon_dies=True)
        res = await r.run_command("netscan 10.0.1.0/24", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("offline", res.output.lower())

    async def test_c2_unavailable_is_reported_as_a_value(self):
        r, c2 = _router(c2_down=True)
        res = await r.run_command("whoami", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertIn("c2", res.output.lower())

class TestOutputHandling(IsolatedAsyncioTestCase):
    async def test_long_output_is_truncated_with_flag(self):
        r, _ = _router(beacon_output="X" * 9000, truncate_chars=4000)
        res = await r.run_command("cat /var/log/big", beacon_id="raccoon-fox")
        self.assertTrue(res.truncated)
        self.assertLess(len(res.output), 4200)

    async def test_nonzero_exit_is_not_an_exception(self):
        r, _ = _router(beacon_exit=1, beacon_output="permission denied")
        res = await r.run_command("cat /etc/shadow", beacon_id="raccoon-fox")
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 1)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_router -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/executor/beacon.py` and `server_tool.py`**

`run_on_beacon` ruft `c2.queue_task(..., lane="agent")` und dann `c2.await_task(...)` mit einer `is_alive`-Rückfrage, die den Agent-Status über `c2.get_agent` prüft (`status != "offline"`). `BeaconGone` wird zu `ActionResult(success=False, output="[beacon offline]")`. `C2Unavailable` zu `ActionResult(success=False, output="[c2 unavailable: …]")`.

`run_on_server` zerlegt den Befehl mit `shlex.split` in argv, ruft `c2.exec_server_tool(argv, ...)` und `c2.await_server_tool(...)`. Das werkzeugspezifische Timeout wird über den Basenamen von `argv[0]` aufgelöst (Spec §9.2), `sudo` wird dabei übersprungen.

Beide liefern immer ein `ActionResult`, nie eine Exception.

- [ ] **Step 4: Implement `software/agent/executor/router.py`**

Die Reihenfolge ist die eigentliche Festlegung und muss genau so sein:

```
1. has_shell_metachars        → blockiert
2. scope.check                → blockiert (fail-closed)
3. safety.classify            → Stufe 1 blockiert sofort
4. Stufe 2 → gate.request     → Ablehnung blockiert
5. safety.enforce_scan_limits
6. Pfadwahl: server_side oder beacon_id
7. Ausführung
8. gate.scan_for_detection auf der Ausgabe
9. loop.truncate
```

Scope vor Klassifikation, weil ein Ziel außerhalb des Scopes auch dann abgelehnt wird, wenn die Aktion harmlos ist. Gate nach der Klassifikation, weil es die Risikowerte braucht.

`target_kind` liefert `"dropbox"`, wenn die Caps des Beacons `"sniffer"` enthalten, sonst `"beacon"`; für serverseitige Läufe `"server"`. Das steuert, welche Stufe-1-Muster greifen (Bridge und NAC-Bypass nur auf der Drop-Box).

`host_was_responsive` für `scan_for_detection` wird aus `findings` abgeleitet: existiert ein früherer Fund zum Zielhost, gilt er als vorher erreichbar.

Liefert `gate.note_detection` `True`, wird `RouterAborted` geworfen — der Kampagnen-Lebenszyklus in Task 13 fängt das.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_router -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/agent/executor/ software/tests/test_agent_router.py
git commit -m "feat(agent): add execution router with gating and detection scanning"
```

---

### Task 12: Werkzeuge und Preambles

**Files:**
- Create: `software/agent/tools/__init__.py`, `software/agent/tools/registry.py`, `software/agent/tools/recon.py`, `software/agent/tools/memory.py`, `software/agent/tools/scoring.py`, `software/agent/tools/scripts.py`, `software/agent/tools/vuln.py`, `software/agent/prompts.py`
- Test: `software/tests/test_agent_tools.py`, `software/tests/test_agent_prompts.py`

**Interfaces:**
- Consumes: `Tool`, `ToolSpec` (Task 6); `Router.run_command` (Task 11); alle `queries.*` (Task 1); `provider.TIER_LIMITS` (Task 5)
- Produces:
  - `registry.executor_tools(router, conn, run_id, *, caps, tier) -> List[Tool]`
  - `registry.orchestrator_tools(conn, run_id, *, dispatch_single, dispatch_parallel, tier) -> List[Tool]`
  - `prompts.orchestrator(caps_by_beacon, scope, phases, tier) -> str`
  - `prompts.executor(caps, scope, tier) -> str`
  - `prompts.capability_section(caps_by_beacon) -> str`

**Werkzeuge in diesem Plan.** `get_wire_intel` und die Wifi-Werkzeuge gehören zu ihren Teilprojekten und werden hier **nicht** angelegt — `registry` muss sie aber über Capability-Filterung aufnehmen können.

| Tool | Rolle | Argumente |
|---|---|---|
| `run_command` | Executor | `command`, `beacon_id?`, `server_side?`, `timeout?`, `p_success_estimate?` |
| `log_discovery` | Executor | `host?`, `finding_type`, `data` |
| `check_exploit` | Executor | `cve_id` |
| `lookup_cve` | Executor | `service`, `version` |
| `save_memory` | Executor | `content`, `sector?`, `topic_key?` |
| `search_memory` | Executor | `query`, `limit?` |
| `save_script` | beide | `name`, `code`, `language`, `description`, `tags?` |
| `search_scripts` | beide | `query`, `limit?` |
| `run_script` | beide | `name`, `timeout?` |
| `dispatch_task` | Orchestrator | `task_name`, `task_description` |
| `dispatch_parallel_tasks` | Orchestrator | `tasks: [{name, description}]` |
| `set_phase` | Orchestrator | `phase`, `note?` |
| `remember_finding` | Orchestrator | `host`, `finding_type`, `data` |
| `recall_findings` | Orchestrator | `host` |
| `get_run_summary` | Orchestrator | — |
| `log_score` | Orchestrator | `action`, `risk_level?` |
| `get_score_context` | Orchestrator | — |

- [ ] **Step 1: Write the failing tests**

```python
class TestToolSurfaces(unittest.TestCase):
    def test_executor_has_no_dispatch_tools(self):
        names = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                               caps=["batch"], tier="full"))
        self.assertNotIn("dispatch_task", names)
        self.assertNotIn("dispatch_parallel_tasks", names)

    def test_executor_has_no_scoring_tools(self):
        names = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                               caps=["batch"], tier="full"))
        self.assertNotIn("log_score", names)
        self.assertNotIn("get_score_context", names)

    def test_orchestrator_has_no_run_command(self):
        names = _names(registry.orchestrator_tools(
            _conn(), 1, dispatch_single=_noop, dispatch_parallel=_noop, tier="full"))
        self.assertNotIn("run_command", names)

    def test_orchestrator_surface_matches_the_spec_count(self):
        names = _names(registry.orchestrator_tools(
            _conn(), 1, dispatch_single=_noop, dispatch_parallel=_noop, tier="full"))
        self.assertEqual(len(names), 11)

    def test_wire_tool_absent_without_sniffer_cap(self):
        names = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                               caps=["batch"], tier="full"))
        self.assertNotIn("get_wire_intel", names)

    def test_reduced_tier_offers_fewer_tools_than_full(self):
        full = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                              caps=["batch"], tier="full"))
        red = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                             caps=["batch"], tier="reduced"))
        mini = _names(registry.executor_tools(_router_stub(), _conn(), 1,
                                              caps=["batch"], tier="minimal"))
        self.assertLess(len(red), len(full))
        self.assertLess(len(mini), len(red))
        self.assertIn("run_command", mini)
        self.assertIn("log_discovery", mini)

    def test_every_tool_spec_has_a_description_and_schema(self):
        for t in registry.executor_tools(_router_stub(), _conn(), 1,
                                         caps=["batch"], tier="full"):
            self.assertTrue(t.spec.description.strip(), t.spec.name)
            self.assertEqual(t.spec.parameters["type"], "object")

class TestToolBehaviour(IsolatedAsyncioTestCase):
    async def test_run_command_returns_success_false_on_block(self):
        tools = registry.executor_tools(_router_stub(blocks=True), _conn(), 1,
                                        caps=["batch"], tier="full")
        out = await _call(tools, "run_command", command="kill",
                          beacon_id="raccoon-fox")
        self.assertFalse(out["success"])

    async def test_log_score_rejects_unknown_action_and_lists_valid_ones(self):
        conn = _conn(); rid = _run(conn)
        tools = registry.orchestrator_tools(conn, rid, dispatch_single=_noop,
                                            dispatch_parallel=_noop, tier="full")
        out = await _call(tools, "log_score", action="hack_the_planet")
        self.assertIn("error", out)
        self.assertIn("host_discovered", str(out))

    async def test_log_score_awards_the_spec_point_value(self):
        conn = _conn(); rid = _run(conn)
        tools = registry.orchestrator_tools(conn, rid, dispatch_single=_noop,
                                            dispatch_parallel=_noop, tier="full")
        self.assertEqual((await _call(tools, "log_score",
                                      action="rce_achieved"))["points"], 200)
        self.assertEqual((await _call(tools, "log_score",
                                      action="detection"))["points"], -100)

    async def test_wifi_score_actions_are_accepted(self):
        conn = _conn(); rid = _run(conn)
        tools = registry.orchestrator_tools(conn, rid, dispatch_single=_noop,
                                            dispatch_parallel=_noop, tier="full")
        for action, pts in (("ap_discovered", 5), ("handshake_captured", 30),
                            ("pmkid_captured", 30), ("wps_pin_found", 50),
                            ("psk_cracked", 75)):
            self.assertEqual((await _call(tools, "log_score", action=action))["points"],
                             pts)

    async def test_set_phase_persists_and_rejects_out_of_range(self):
        conn = _conn(); rid = _run(conn)
        tools = registry.orchestrator_tools(conn, rid, dispatch_single=_noop,
                                            dispatch_parallel=_noop, tier="full")
        await _call(tools, "set_phase", phase=3)
        self.assertEqual(queries.get_run(conn, rid)["phase"], 3)
        self.assertIn("error", await _call(tools, "set_phase", phase=99))

    async def test_run_script_validates_before_executing(self):
        conn = _conn()
        queries.save_script(conn, "bad", "rm -rf /opt/raccoon", "bash", "d", "[]")
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        out = await _call(tools, "run_script", name="bad")
        self.assertFalse(out["success"])

    async def test_save_script_refuses_blocked_code(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        out = await _call(tools, "save_script", name="x", code="rm -rf /",
                          language="bash", description="d")
        self.assertIn("error", out)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0], 0)

    async def test_recall_findings_returns_count_and_entries(self):
        conn = _conn(); rid = _run(conn)
        queries.log_finding(conn, rid, "10.0.1.5", "service", "SMB 3.1.1", "exec")
        tools = registry.orchestrator_tools(conn, rid, dispatch_single=_noop,
                                            dispatch_parallel=_noop, tier="full")
        out = await _call(tools, "recall_findings", host="10.0.1.5")
        self.assertEqual(out["count"], 1)

class TestVulnLookup(IsolatedAsyncioTestCase):
    async def test_lookup_cve_caches_and_reuses(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            first = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
            second = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(first["cves"][0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(second["cves"][0]["severity"], "CRITICAL")
        self.assertEqual(len(calls), 1, "zweiter Aufruf muss aus dem Cache kommen")

    async def test_expired_cache_entry_is_refetched(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]):
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        conn.execute("UPDATE cve_cache SET fetched_at = ?", (_iso_days_ago(8),))
        with _fake_osv(hits=[_cve("CVE-2021-44228", 10.0)]) as calls:
            await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(len(calls), 1)

    async def test_unreachable_cve_source_returns_a_warning_not_an_error(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        with _fake_osv(unreachable=True):
            out = await _call(tools, "lookup_cve", service="log4j", version="2.14.1")
        self.assertEqual(out["cves"], [])
        self.assertIn("warning", out)

    async def test_check_exploit_reports_missing_searchsploit_as_warning(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        with _no_searchsploit():
            out = await _call(tools, "check_exploit", cve_id="CVE-2021-44228")
        self.assertFalse(out["has_exploit"])
        self.assertIn("searchsploit", out["warning"])

    async def test_check_exploit_accepts_both_cve_spellings(self):
        conn = _conn()
        tools = registry.executor_tools(_router_stub(), conn, 1,
                                        caps=["batch"], tier="full")
        with _fake_searchsploit(results=[{"Title": "x", "EDB-ID": "48745",
                                          "Type": "remote"}]) as calls:
            await _call(tools, "check_exploit", cve_id="CVE-2021-44228")
            await _call(tools, "check_exploit", cve_id="2021-44228")
        self.assertEqual(calls, ["2021-44228", "2021-44228"])

class TestPrompts(unittest.TestCase):
    def test_capability_section_lists_each_beacon(self):
        s = prompts.capability_section({"raccoon-fox": ["batch", "posix"],
                                        "raccoon-pi": ["batch", "sniffer"]})
        self.assertIn("raccoon-fox", s)
        self.assertIn("sniffer", s)

    def test_orchestrator_prompt_contains_scope_and_phases(self):
        p = prompts.orchestrator({"raccoon-fox": ["batch"]},
                                 scope=_scope(), phases={1, 2, 3}, tier="full")
        self.assertIn("10.0.1.0/24", p)
        self.assertIn("10.0.9.0/24", p)

    def test_orchestrator_prompt_lists_every_score_action(self):
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                 phases={1, 2, 3, 4, 5}, tier="full")
        for a in ("host_discovered", "rce_achieved", "detection",
                  "ap_discovered", "psk_cracked", "pmkid_captured"):
            self.assertIn(a, p)

    def test_orchestrator_prompt_states_the_scan_rate_limits(self):
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                 phases={1, 2, 3}, tier="full")
        self.assertIn("-T2", p)
        self.assertIn("--max-rate 50", p)

    def test_orchestrator_prompt_demands_individual_targets(self):
        """Folgt aus fail-closed Scope — das Modell muss es wissen."""
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                 phases={1, 2}, tier="full")
        self.assertRegex(p.lower(), r"einzeln|individually|one target per")

    def test_orchestrator_prompt_warns_about_the_gate(self):
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                 phases={1, 2}, tier="full")
        self.assertRegex(p.lower(), r"gate|freigabe|approval")

    def test_disabled_phases_are_not_advertised(self):
        p = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                 phases={1, 2, 3}, tier="full")
        self.assertNotIn("Phase 5", p)

    def test_wire_phase_only_with_sniffer_cap(self):
        with_pi = prompts.orchestrator({"raccoon-pi": ["sniffer"]}, scope=_scope(),
                                       phases={1, 2}, tier="full")
        without = prompts.orchestrator({"raccoon-fox": ["batch"]}, scope=_scope(),
                                       phases={1, 2}, tier="full")
        self.assertIn("Wire Intel", with_pi)
        self.assertNotIn("Wire Intel", without)

    def test_executor_prompt_forbids_scope_expansion(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        self.assertRegex(p.lower(), r"nicht ausweiten|do not expand|nicht abschweifen")

    def test_executor_prompt_fixes_the_output_format(self):
        p = prompts.executor(["batch"], scope=_scope(), tier="full")
        for marker in ("TASK:", "STATUS:", "FINDINGS:"):
            self.assertIn(marker, p)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_tools software.tests.test_agent_prompts -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement the tool modules**

Jedes Tool ist eine `async def` plus ein `ToolSpec`. Vier Festlegungen:

`SCORE_ACTIONS` als Dict mit allen 16 Aktionen aus Spec §10.8, einschließlich der fünf Wifi-Aktionen. Eine unbekannte Aktion liefert `{"error": …, "valid_actions": [...]}` — die Liste geht mit, damit das Modell sich korrigieren kann.

`run_command` reicht `p_success_estimate` als `p_success_override` an den Router durch. Das ist die einzige Stelle, an der das Modell die EV-Rechnung beeinflussen kann, und der Router klammert den Wert.

`save_script` und `run_script` rufen beide `safety.validate_script`; ein Treffer verhindert das Speichern bzw. die Ausführung.

`registry` filtert zweistufig: erst nach Capability (ein Tool deklariert `requires_caps`), dann nach `tier` (jedes Tool deklariert, in welchen `tool_set`-Stufen es erscheint — `"bare"`, `"core"`, `"all"`).

**`vuln.py` enthält die CVE-Pipeline** (Spec §11, bei Eugene gebaut aber nie angeschlossen). Reihenfolge, dokumentiert als Kommentar im Modul:

```
1. Eingaben normalisieren, Cache-Schlüssel bilden (service + version)
2. cve_cache prüfen, TTL 7 Tage
3. OSV.dev abfragen (Primärquelle, keine Ratenbegrenzung)
4. Fehlende CVSS-Werte aus NVD nachladen, höchstens 5 Aufrufe, ratenbegrenzt
5. Liefert OSV nichts, auf NVD-CPE-Abfrage zurückfallen
6. Ergebnisse in cve_cache schreiben
7. Zurückgeben
```

**Keine Stufe wirft.** Jeder Ausfall wird als `{"cves": [], "warning": …}` geliefert — eine nicht erreichbare CVE-Quelle darf eine Kampagne nicht beenden. Die NVD-Ratenbegrenzung ist ein minimaler Abstand zwischen Aufrufen (6 Sekunden ohne API-Key, kürzer mit), `severity` wird aus dem CVSS-Score abgeleitet (≥9.0 CRITICAL, ≥7.0 HIGH, ≥4.0 MEDIUM, >0 LOW, sonst UNKNOWN).

`check_exploit` ruft `searchsploit --json --cve <id>` und **parst stdout auch bei Exit-Code ≠ 0** — searchsploit liefert verwertbare Ausgabe mit nicht-null Rückgabewert. Ein führendes `CVE-` wird abgeschnitten. Fehlt das Binary, ist das eine `warning`, kein Fehler.

- [ ] **Step 4: Implement `software/agent/prompts.py`**

Aufbau nach Spec §12. Der Orchestrator-Preamble setzt sich zusammen aus: Rollenbeschreibung, `capability_section`, Werkzeugbeschreibungen, vollständige Punktetabelle, EV-Gating mit der CVSS-Richtlinie aus Spec §10.8, Scan-Ratenlimits mit den konkreten Flags, der aktive Scope mit der Anweisung Ziele einzeln zu benennen, die Stufe-1- und Stufe-2-Listen mit dem Hinweis auf das Gate, und die freigegebenen Phasen.

Phasen werden **nur aufgeführt, wenn sie freigegeben sind** — ein gesperrtes Phase 5 taucht im Preamble nicht auf, damit das Modell nicht auf eine Wand plant. Die Wire-Intel-Phase erscheint nur, wenn mindestens ein Beacon `sniffer` meldet; die Wifi-Phasen nur bei `wifi:monitor`.

Der Executor-Preamble ist kurz: eine Aufgabe, die Werkzeuge, striktes Scope-Verbot, festes Ausgabeformat `TASK/STATUS/FINDINGS/ERRORS`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_tools software.tests.test_agent_prompts -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/agent/tools/ software/agent/prompts.py software/tests/test_agent_tools.py software/tests/test_agent_prompts.py
git commit -m "feat(agent): add LLM tool surfaces and campaign preambles"
```

---

### Task 13: Orchestrator — Lebenszyklus, Dispatch, Pause, Waisen

**Files:**
- Create: `software/agent/orchestrator.py`
- Test: `software/tests/test_agent_orchestrator.py`

**Interfaces:**
- Consumes: `loop.run`, `Tool` (Task 6); `registry.*`, `prompts.*` (Task 12); `Router` (Task 11); `Gate`, `GatePauseRequested` (Task 4); `C2Client` (Task 8); `AgentConfig`, `CampaignConfig` (Task 7); `provider.TIER_LIMITS` (Task 5)
- Produces:
  - `Campaign(agent_cfg, campaign_cfg, conn, c2, client)` 
  - `await Campaign.start() -> int` — liefert `run_id`, läuft im Hintergrund weiter
  - `await Campaign.wait() -> str` — Endbericht
  - `Campaign.pause()`, `await Campaign.resume()`, `Campaign.stop()`
  - `Campaign.status() -> dict` — `run_id`, `status`, `phase`, Score, Detections, Budgets, Stream-Länge
  - `Campaign.stream(since: int = 0) -> List[dict]` — Ereignisse für das GUI
  - `Campaign.gate -> Gate`
  - `await orchestrator.restore_orphans(conn, c2) -> List[int]` — setzt Beacon-Intervalle verwaister Läufe zurück
  - `CampaignManager` — hält laufende Kampagnen je `run_id`, `active() -> List[dict]`, `running_run_ids -> Set[int]`
  - `BudgetExceeded` — Exception, wenn Token- oder Laufzeit-Budget überschritten ist

- [ ] **Step 1: Write the failing tests**

```python
class TestLifecycle(IsolatedAsyncioTestCase):
    async def test_run_record_is_created_and_completed(self):
        conn, c2 = _env()
        client = mock.MockClient([mock.text("Kampagne abgeschlossen")])
        camp = _campaign(conn, c2, client)
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")

    async def test_beacon_interval_lowered_at_start_and_restored_at_end(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start()
        await camp.wait()
        self.assertEqual(c2.interval_calls[0][1], 15)
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_interval_restored_even_when_the_llm_fails(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.FailingClient("kein Kontakt"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_detection_budget_abort_sets_aborted_and_restores(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         raise_from_router=router.RouterAborted("budget"))
        rid = await camp.start()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.interval_calls[-1][1], 300)

class TestDispatch(IsolatedAsyncioTestCase):
    async def test_dispatch_task_returns_the_executor_result(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "scan",
                                          "task_description": "scan 10.0.1.5"})),
            mock.text("ergebnis gesehen"),
            mock.text("TASK: scan\nSTATUS: success\nFINDINGS:\n  - 445 offen")])
        camp = _campaign(conn, c2, client)
        await camp.start(); await camp.wait()
        row = conn.execute("SELECT status, result FROM tasks").fetchone()
        self.assertEqual(row["status"], "completed")
        self.assertIn("445", row["result"])

    async def test_parallel_dispatch_returns_both_sections(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "t1", "description": "d1"},
                {"name": "t2", "description": "d2"}]})),
            mock.text("beide gesehen"),
            mock.text("TASK: t1\nSTATUS: success"),
            mock.text("TASK: t2\nSTATUS: success")])
        camp = _campaign(conn, c2, client)
        await camp.start(); await camp.wait()
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 2)

    async def test_failing_executor_yields_an_error_string_not_an_exception(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t", "task_description": "d"})),
            mock.text("fehler verstanden")])   # Warteschlange für den Executor leer
        camp = _campaign(conn, c2, client)
        await camp.start()
        self.assertIsInstance(await camp.wait(), str)
        self.assertIn(conn.execute("SELECT status FROM tasks").fetchone()["status"],
                      ("failed", "running"))

    async def test_semaphore_of_one_serialises_without_deadlock(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_parallel_tasks", {"tasks": [
                {"name": "t1", "description": "d1"},
                {"name": "t2", "description": "d2"}]})),
            mock.text("ok"), mock.text("r1"), mock.text("r2")])
        camp = _campaign(conn, c2, client, max_concurrent=1)
        await camp.start()
        await asyncio.wait_for(camp.wait(), timeout=10)

    async def test_task_row_records_the_current_phase(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 3})),
            mock.calls(("dispatch_task", {"task_name": "t", "task_description": "d"})),
            mock.text("fertig"), mock.text("r")])
        camp = _campaign(conn, c2, client)
        await camp.start(); await camp.wait()
        self.assertEqual(conn.execute("SELECT phase FROM tasks").fetchone()["phase"], 3)

class TestBudgets(IsolatedAsyncioTestCase):
    async def test_token_budget_aborts_the_campaign(self):
        conn, c2 = _env()
        client = mock.MockClient([mock.text("x", total_tokens=400_000),
                                  mock.text("y", total_tokens=400_000)])
        camp = _campaign(conn, c2, client, max_tokens_total=500_000)
        rid = await camp.start(); await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")

    async def test_runtime_budget_aborts_the_campaign(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client(), max_runtime_seconds=0.1)
        rid = await camp.start(); await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")

class TestPauseResume(IsolatedAsyncioTestCase):
    async def test_pause_sets_status_and_keeps_the_lowered_interval(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.pause()
        await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertNotIn(300, [i[1] for i in c2.interval_calls])

    async def test_pause_lets_an_in_flight_executor_finish(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t", "task_description": "d"})),
            mock.text("ok"), mock.text("executor fertig")])
        camp = _campaign(conn, c2, client)
        await camp.start()
        await asyncio.sleep(0.02)
        camp.pause()
        await camp.wait()
        self.assertEqual(conn.execute("SELECT status FROM tasks").fetchone()["status"],
                         "completed")

    async def test_resume_continues_the_same_run_with_fresh_budget(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.pause(); await camp.wait()
        camp.client = mock.MockClient([mock.text("jetzt fertig")])
        await camp.resume(); await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "completed")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)

    async def test_gate_pause_request_pauses_the_campaign(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("x")]),
                         raise_from_router=gate.GatePauseRequested("knock"))
        rid = await camp.start(); await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")

    async def test_stop_sets_aborted_and_restores_the_interval(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, _slow_client())
        rid = await camp.start()
        await asyncio.sleep(0.05)
        camp.stop(); await camp.wait()
        self.assertEqual(queries.get_run(conn, rid)["status"], "aborted")
        self.assertEqual(c2.interval_calls[-1][1], 300)

class TestOrphanRecovery(IsolatedAsyncioTestCase):
    """Review Focus 5: Absturz bei abgesenktem Intervall."""
    async def test_restore_orphans_resets_intervals_of_unfinished_runs(self):
        conn, c2 = _env()
        rid = queries.create_run(conn, "campaign", None, "auto",
                                 json.dumps({"beacons": ["raccoon-fox"],
                                             "restore_interval": 300}))
        restored = await orchestrator.restore_orphans(conn, c2)
        self.assertIn(rid, restored)
        self.assertEqual(c2.interval_calls[-1], ("raccoon-fox", 300, 20))

    async def test_restore_orphans_marks_running_runs_as_failed(self):
        conn, c2 = _env()
        rid = queries.create_run(conn, "campaign", None, "auto",
                                 json.dumps({"beacons": ["raccoon-fox"],
                                             "restore_interval": 300}))
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(queries.get_run(conn, rid)["status"], "failed")

    async def test_paused_runs_keep_their_status_but_get_intervals_restored(self):
        conn, c2 = _env()
        rid = queries.create_run(conn, "campaign", None, "auto",
                                 json.dumps({"beacons": ["raccoon-fox"],
                                             "restore_interval": 300}))
        queries.set_run_status(conn, rid, "paused")
        await orchestrator.restore_orphans(conn, c2)
        self.assertEqual(queries.get_run(conn, rid)["status"], "paused")
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_unreachable_c2_does_not_prevent_startup(self):
        conn, c2 = _env(c2_down=True)
        queries.create_run(conn, "campaign", None, "auto",
                           json.dumps({"beacons": ["raccoon-fox"]}))
        self.assertIsInstance(await orchestrator.restore_orphans(conn, c2), list)

class TestStream(IsolatedAsyncioTestCase):
    async def test_stream_records_dispatches_and_decisions(self):
        conn, c2 = _env()
        client = mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "scan",
                                          "task_description": "d"})),
            mock.text("fertig"), mock.text("r")])
        camp = _campaign(conn, c2, client)
        await camp.start(); await camp.wait()
        kinds = {e["kind"] for e in camp.stream()}
        self.assertIn("dispatch", kinds)

    async def test_stream_since_returns_only_newer_events(self):
        conn, c2 = _env()
        camp = _campaign(conn, c2, mock.MockClient([mock.text("fertig")]))
        await camp.start(); await camp.wait()
        all_events = camp.stream()
        self.assertEqual(camp.stream(since=len(all_events)), [])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_orchestrator -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/orchestrator.py`**

Der Lebenszyklus in `_run`:

```
try:
    für jeden Ziel-Beacon: c2.set_beacon_interval(bid, campaign_interval, jitter)
    status = "running"
    ergebnis = await loop.run(client, system=prompts.orchestrator(...),
                              prompt=<Kampagnenauftrag>,
                              tools=registry.orchestrator_tools(...),
                              max_turns=TIER_LIMITS[tier]["orchestrator_turns"], ...)
    status = "completed"
except GatePauseRequested:        status = "paused"
except RouterAborted:             status = "aborted"
except BudgetExceeded:            status = "aborted"
except ProviderError, Exception:  status = "failed"
finally:
    set_run_status(status)
    wenn status != "paused": für jeden Beacon Intervall auf restore_interval zurück
```

Der **`finally`-Zweig setzt das Intervall nur bei Endzuständen zurück** (Spec §8.7) — bei `paused` bleibt es abgesenkt, weil eine Fortsetzung wahrscheinlich ist.

`dispatch_single` ist die Funktion, die `dispatch_task` hinterlegt bekommt: Semaphor erwerben, `create_task`-Zeile schreiben, Executor über `loop.run` mit `registry.executor_tools` und `TIER_LIMITS[tier]["executor_turns"]` fahren, Ergebnis per `update_task` festhalten. **Jeder Fehler wird zu `"[ERROR] Task '<name>' failed: <e>'"`** und als Rückgabewert geliefert, nie geworfen.

`dispatch_parallel` erwirbt das Semaphor **in der Schleife vor dem Erzeugen der Task** (Spec §8.3) — das ist der Grund, warum `Semaphore(1)` auch hier serialisiert. Danach `asyncio.gather(..., return_exceptions=True)` und Abschnitte als `=== Task: {name} ===\n{result}\n\n` zusammensetzen.

**Pause** setzt ein `asyncio.Event`; `dispatch_single` und `dispatch_parallel` prüfen es, bevor sie einen **neuen** Executor starten, und liefern dann `"[PAUSED] dispatch suspended"`. Laufende Executors werden nicht unterbrochen.

**Budgets** werden in einer Hook geprüft, die nach jeder LLM-Antwort läuft: Token-Summe aus `get_run_token_summary` gegen `max_tokens_total`, verstrichene Zeit gegen `max_runtime_seconds`. Überschreitung wirft `BudgetExceeded`.

`stream` ist eine Liste von `{"seq", "ts", "kind", "text", "detail"}`; `kind` ist eines von `dispatch`, `finding`, `score`, `ev`, `detection`, `phase`, `approval`, `error`, `info`. Sie wird aus den Tool-Aufrufen und Router-Ergebnissen gefüllt und vom GUI über `since` inkrementell abgeholt.

`restore_orphans` liest `list_unfinished_runs`, holt `beacons` und `restore_interval` aus `config_json`, setzt die Intervalle zurück, und markiert `running`-Läufe als `failed` (`paused` bleibt `paused`). Fehler beim C2-Zugriff werden geloggt und übersprungen — der Dienst muss auch ohne erreichbaren C2 starten.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_orchestrator -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add software/agent/orchestrator.py software/tests/test_agent_orchestrator.py
git commit -m "feat(agent): add campaign orchestrator with pause, budgets and orphan recovery"
```

---

### Task 14: Dienst

**Files:**
- Create: `software/agent/service.py`, `software/agent/__main__.py`
- Test: `software/tests/test_agent_service.py`

**Interfaces:**
- Consumes: `CampaignManager`, `restore_orphans` (Task 13); `config.load`, `config.available`, `CampaignConfig.from_form` (Task 7); `provider.create_client`, `capability_tier` (Task 5); `db.open_store` (Task 1)
- Produces:
  - `service.make_app(cfg, conn, c2, manager) -> aiohttp.web.Application`
  - `GET /status` → `{"available", "reason", "tier", "provider", "model", "campaigns": [...]}`
  - `GET /beacons` → Flotte mit Capabilities, für das Formular
  - `POST /campaign` → `{"run_id"}` oder `400`/`503`
  - `GET /campaign/<run_id>` → `Campaign.status()`
  - `GET /campaign/<run_id>/stream?since=N` → `{"events": [...], "next": N}`
  - `GET /campaign/<run_id>/approvals` → offene Anklopf-Anfragen
  - `POST /campaign/<run_id>/approve` → `{"approval_id", "allowed"}`
  - `POST /campaign/<run_id>/pause` · `/resume` · `/stop`
  - `service.require_agent_token` — Middleware gegen `X-Agent-Token`

- [ ] **Step 1: Write the failing tests**

```python
class TestStatusWithoutProvider(AioHTTPTestCase):
    """Spec §19.1: Dienst läuft, kein Anbieter konfiguriert."""
    async def get_application(self):
        return _app(cfg=_cfg(provider=None))

    async def test_status_reports_unavailable_with_reason(self):
        body = await (await self.client.get("/status", headers=_H)).json()
        self.assertFalse(body["available"])
        self.assertIn("provider", body["reason"].lower())

    async def test_campaign_start_is_refused_cleanly(self):
        resp = await self.client.post("/campaign", json=_form(), headers=_H)
        self.assertEqual(resp.status, 503)
        self.assertIn("reason", await resp.json())

    async def test_database_is_still_initialised(self):
        self.assertTrue((await (await self.client.get("/status", headers=_H)).json())
                        ["db_ready"])

class TestAuth(AioHTTPTestCase):
    async def get_application(self):
        return _app(agent_token="geheim")

    async def test_missing_token_is_401(self):
        self.assertEqual((await self.client.get("/status")).status, 401)

    async def test_wrong_token_is_401(self):
        self.assertEqual((await self.client.get(
            "/status", headers={"X-Agent-Token": "falsch"})).status, 401)

    async def test_correct_token_passes(self):
        self.assertEqual((await self.client.get(
            "/status", headers={"X-Agent-Token": "geheim"})).status, 200)

class TestCampaignEndpoints(AioHTTPTestCase):
    async def get_application(self):
        return _app(cfg=_cfg(provider="anthropic"), client=mock.MockClient(
            [mock.text("fertig")]))

    async def test_start_returns_a_run_id(self):
        body = await (await self.client.post("/campaign", json=_form(),
                                             headers=_H)).json()
        self.assertIn("run_id", body)

    async def test_empty_scope_is_a_400(self):
        form = _form(); form["scope_allow"] = []
        self.assertEqual((await self.client.post("/campaign", json=form,
                                                 headers=_H)).status, 400)

    async def test_no_beacons_is_a_400(self):
        form = _form(); form["beacons"] = []
        self.assertEqual((await self.client.post("/campaign", json=form,
                                                 headers=_H)).status, 400)

    async def test_status_of_unknown_run_is_404(self):
        self.assertEqual((await self.client.get("/campaign/9999",
                                                headers=_H)).status, 404)

    async def test_stream_is_incremental(self):
        rid = (await (await self.client.post("/campaign", json=_form(),
                                             headers=_H)).json())["run_id"]
        first = await (await self.client.get(f"/campaign/{rid}/stream",
                                             headers=_H)).json()
        second = await (await self.client.get(
            f"/campaign/{rid}/stream?since={first['next']}", headers=_H)).json()
        self.assertEqual(second["events"], [])

    async def test_beacons_endpoint_exposes_capabilities(self):
        body = await (await self.client.get("/beacons", headers=_H)).json()
        self.assertIn("caps", body["beacons"][0])

class TestApprovalFlow(AioHTTPTestCase):
    async def get_application(self):
        return _app(cfg=_cfg(provider="anthropic", mode="supervised"))

    async def test_pending_approval_is_listed_and_can_be_answered(self):
        rid = await _start_campaign_awaiting_approval(self.client)
        pend = await (await self.client.get(f"/campaign/{rid}/approvals",
                                            headers=_H)).json()
        self.assertEqual(len(pend["approvals"]), 1)
        resp = await self.client.post(
            f"/campaign/{rid}/approve",
            json={"approval_id": pend["approvals"][0]["id"], "allowed": True},
            headers=_H)
        self.assertEqual(resp.status, 200)

    async def test_answering_an_unknown_approval_is_404(self):
        rid = (await (await self.client.post("/campaign", json=_form(),
                                             headers=_H)).json())["run_id"]
        self.assertEqual((await self.client.post(
            f"/campaign/{rid}/approve", json={"approval_id": 9999, "allowed": True},
            headers=_H)).status, 404)

class TestLifecycleEndpoints(AioHTTPTestCase):
    async def get_application(self):
        return _app(cfg=_cfg(provider="anthropic"), client=_slow_client())

    async def test_pause_then_resume(self):
        rid = (await (await self.client.post("/campaign", json=_form(),
                                             headers=_H)).json())["run_id"]
        self.assertEqual((await self.client.post(f"/campaign/{rid}/pause",
                                                 headers=_H)).status, 200)
        self.assertEqual((await self.client.post(f"/campaign/{rid}/resume",
                                                 headers=_H)).status, 200)

    async def test_stop_marks_the_run_aborted(self):
        rid = (await (await self.client.post("/campaign", json=_form(),
                                             headers=_H)).json())["run_id"]
        await self.client.post(f"/campaign/{rid}/stop", headers=_H)
        body = await (await self.client.get(f"/campaign/{rid}", headers=_H)).json()
        self.assertIn(body["status"], ("aborted", "running"))

class TestStartup(unittest.IsolatedAsyncioTestCase):
    async def test_startup_runs_orphan_recovery(self):
        conn, c2 = _env()
        queries.create_run(conn, "campaign", None, "auto",
                           json.dumps({"beacons": ["raccoon-fox"],
                                       "restore_interval": 300}))
        await service.on_startup(_cfg(provider=None), conn, c2, _manager())
        self.assertEqual(c2.interval_calls[-1][1], 300)

    async def test_startup_succeeds_without_a_reachable_c2(self):
        conn, c2 = _env(c2_down=True)
        await service.on_startup(_cfg(provider=None), conn, c2, _manager())
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_service -v`
Expected: FAIL mit `ModuleNotFoundError`

- [ ] **Step 3: Implement `software/agent/service.py`**

aiohttp-Anwendung mit den Endpunkten aus dem Interfaces-Block. Die Middleware vergleicht `X-Agent-Token` per `hmac.compare_digest`; ist in der Konfiguration kein Token gesetzt, wird nur von Loopback akzeptiert.

`POST /campaign` prüft in dieser Reihenfolge: `config.available()` → `503` mit Grund; `CampaignConfig.from_form` → `ConfigError` wird `400`; dann `create_client`, `Campaign`, `manager.add`, `await camp.start()`, Rückgabe der `run_id`. **Ein nicht konfigurierter Anbieter darf nie zu einem Stacktrace führen** (Spec §19.1).

`on_startup` ruft `restore_orphans` und fängt dabei alle Ausnahmen — der Dienst startet auch, wenn der C2 nicht erreichbar ist.

`GET /status` liefert zusätzlich `db_ready` und die Fähigkeitsstufe, damit das GUI begründen kann, warum Phase 5 gesperrt ist.

- [ ] **Step 4: Implement `software/agent/__main__.py`**

`config.load()`, `db.open_store`, `C2Client`, `CampaignManager`, `make_app`, `web.run_app(host=cfg.bind_host, port=cfg.bind_port)`. Logging über `logging.basicConfig` mit dem Format aus dem Repo. Startet auch ohne Anbieter — dann ist nur `/status` sinnvoll nutzbar.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_service -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add software/agent/service.py software/agent/__main__.py software/tests/test_agent_service.py
git commit -m "feat(agent): add aiohttp service with campaign and approval endpoints"
```

---

### Task 15: GUI — drei Regionen

**Files:**
- Create: `software/c2/static/agent.css`, `software/c2/static/agent.js`
- Modify: `software/c2/server.py` — ein `<script src>` und ein `<link rel>` im `_OPERATOR_HTML`-Literal (`server.py:1930-1955`)
- Test: `software/tests/test_c2_agent_gui.py`

**Interfaces:**
- Consumes: `/api/ai/status`, `/api/ai/campaign/<rid>`, `/api/ai/campaign/<rid>/stream`, `/api/ai/campaign/<rid>/approvals`, `/api/ai/campaign/<rid>/approve`, `/api/ai/campaign/<rid>/pause|resume|stop` (Task 9 + 14)
- Produces: globale JS-Funktionen `agentInit()`, `agentOpenPanel()`, `agentRenderDrawer(status)`, `agentRenderStream(events)`, `agentAnswerApproval(id, allowed)` — Task 16 baut darauf auf

**Das GUI hat im Repo keine JS-Testinfrastruktur.** Automatisiert wird hier deshalb nur, was von Python aus prüfbar ist: Ausliefern der Dateien und die Unversehrtheit des bestehenden GUI. Das Verhalten im Browser wird in Schritt 6 manuell gegen die laufende Anwendung geprüft — mit explizit benannten Erwartungen.

- [ ] **Step 1: Write the failing tests**

```python
class TestStaticAssets(ServerTestBase):
    def test_agent_js_is_served(self):
        self.assertEqual(self.client.get("/static/agent.js").status_code, 200)

    def test_agent_css_is_served(self):
        self.assertEqual(self.client.get("/static/agent.css").status_code, 200)

    def test_index_references_both_assets(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("/static/agent.js", html)
        self.assertIn("/static/agent.css", html)

class TestGuiDegradation(ServerTestBase):
    """Spec §19.2: ohne Agent-Dienst bleibt das GUI bedienbar."""
    def test_index_still_renders_without_agent_service(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("{{TOKEN}}".replace("{{TOKEN}}", TEST_TOKEN), html)
        self.assertIn("Raccoon C2", html)

    def test_button_is_not_hardcoded_in_the_html_literal(self):
        """Der Knopf kommt aus agent.js — fehlt die Datei, fehlt nur der Knopf."""
        html = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("Automated Attack", html)

    def test_agent_js_inserts_the_button_itself(self):
        js = Path("software/c2/static/agent.js").read_text()
        self.assertIn("Automated Attack", js)

    def test_every_ai_fetch_is_guarded(self):
        """Ein 503 darf keine bestehende setInterval-Schleife abreißen."""
        js = Path("software/c2/static/agent.js").read_text()
        for call in re.findall(r"fetch\(\s*[`'\"]/api/ai[^)]*\)", js):
            idx = js.index(call)
            self.assertIn("try", js[max(0, idx - 400):idx],
                          f"ungeschützter fetch: {call}")

    def test_status_is_not_polled_continuously(self):
        js = Path("software/c2/static/agent.js").read_text()
        self.assertNotRegex(js, r"setInterval\([^)]*api/ai/status")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_c2_agent_gui -v`
Expected: FAIL — `/static/agent.js` liefert 404

- [ ] **Step 3: Implement `software/c2/static/agent.css`**

Die drei Regionen aus Spec §17.1, in der bestehenden Palette. Variablen werden aus `:root` des Haupt-GUI geerbt; neu hinzu kommen `--ai: #ff6600` für Agent-Herkunft und `--op: #33ccff` für Operator-Herkunft.

Klassen: `.ai-pane` (oberer Stream, `resize`-Griff), `.ai-pane-collapsed`, `.ai-grip`, `.ai-drawer`, `.ai-gauge`, `.ai-knock`, `.ai-badge` / `.ai-badge.op`, `.ai-scope-ok` / `.ai-scope-no`, `.ai-btn` / `.ai-btn.live` / `.ai-btn.disabled`.

- [ ] **Step 4: Implement `software/c2/static/agent.js`**

`agentInit()` läuft bei `DOMContentLoaded`:

1. Den Knopf **selbst** in die Toolbar einfügen — er steht nicht im HTML-Literal, damit eine fehlende Datei nur den Knopf kostet (Spec §19.2).
2. Einmal `GET /api/ai/status`. Jeder Zugriff auf `/api/ai/*` steckt in `try/catch`; bei `503` oder `available: false` wird der Knopf als `.ai-btn.disabled` mit `title` gerendert, der den Grund nennt.
3. Keine Dauer-Abfrage gegen einen nicht vorhandenen Dienst — Status nur beim Laden und beim Klick.

Bei laufender Kampagne: Stream-Abfrage alle 1,5 s inkrementell über `?since=`, Drawer-Status alle 2 s, Approval-Abfrage alle 1,5 s. Alle drei werden gestoppt, sobald `status` ein Endzustand ist.

Der Toggle **Agent / Alles** schaltet zwischen reiner Agent-Ansicht und einer Zusammenführung mit der Operator-History, sortiert nach Zeitstempel, jede Zeile mit `AI`- oder `OP`-Badge.

Ein Klick auf eine Stream-Zeile öffnet die Details über das bestehende `openPanel()` — vollständige Tool-Argumente, Rohausgabe, zugehörige LLM-Interaktion.

Die Anklopf-Karte im Drawer zeigt beide Gründe und die EV-Zahl und ruft bei Klick `POST /api/ai/campaign/<rid>/approve`.

Toasts laufen über das bestehende `toast()`, damit Agent-Ereignisse im gewohnten Benachrichtigungsbereich erscheinen.

- [ ] **Step 5: Wire the assets into `_OPERATOR_HTML` (`server.py:1930-1955`)**

Ein `<link rel="stylesheet" href="/static/agent.css">` im `<head>` und ein `<script src="/static/agent.js" defer></script>` am Ende des `<body>`. **Mehr nicht** — kein Markup, kein Knopf, keine Funktion im Literal. Das hält die Änderung am 5.388-zeiligen String auf zwei Zeilen.

- [ ] **Step 6: Run the tests to verify they pass, then verify in the browser**

Run: `python -m unittest software.tests.test_c2_agent_gui -v`
Expected: PASS

Dann manuell, mit laufendem C2 **ohne** Agent-Dienst:
- Seite lädt vollständig, Agentenliste und Terminal funktionieren
- „Automated Attack" ist ausgegraut, der Tooltip nennt den Grund
- Browser-Konsole zeigt keine unbehandelte Ausnahme
- Ein Kommando im Terminal absetzen und ein Ergebnis erhalten

Dann mit laufendem Agent-Dienst und einer Testkampagne gegen einen lokalen Beacon:
- Knopf ist aktiv, Kampagne startet
- Oberer Stream zeigt Dispatches und EV-Zeilen in Volltextbreite
- Griff zwischen den Bereichen ist ziehbar, Bereich zuklappbar
- Toggle „Alles" zeigt eigene und Agent-Kommandos chronologisch gemischt
- Drawer zählt Phase, Score, Detections, Tokens und Laufzeit hoch
- Eigenes Kommando im unteren Terminal wird **vor** dem Agent-Plan ausgeführt
- Nach Kampagnenende verschwinden Stream und Drawer

- [ ] **Step 7: Commit**

```bash
git add software/c2/static/agent.css software/c2/static/agent.js software/c2/server.py software/tests/test_c2_agent_gui.py
git commit -m "feat(gui): add agent stream, operator terminal split and campaign drawer"
```

---

### Task 16: GUI — Full-Auto-Formular

**Files:**
- Modify: `software/c2/static/agent.js`, `software/c2/static/agent.css`
- Test: `software/tests/test_c2_agent_gui.py` (erweitern)

**Interfaces:**
- Consumes: `GET /api/ai/beacons`, `GET /api/ai/status`, `POST /api/ai/campaign` (Task 14); `agentOpenPanel` (Task 15)
- Produces: `agentOpenFullAutoForm()`, `agentCollectForm() -> object`, `agentLoadPreset(name)`, `agentSavePreset(name)`

- [ ] **Step 1: Write the failing tests**

```python
class TestFullAutoForm(ServerTestBase):
    def setUp(self):
        self.js = Path("software/c2/static/agent.js").read_text()

    def test_form_has_all_eight_sections(self):
        for label in ("Ziel-Beacons", "Scope", "Phasen", "Risikoprofil",
                      "Anklopfen", "Budget", "Modell", "Zeitplan"):
            self.assertIn(label, self.js)

    def test_phase_five_default_is_off(self):
        self.assertRegex(self.js, r"phase5[^\n]*(false|unchecked)")

    def test_three_risk_presets_are_offered(self):
        for p in ("passive", "normal", "aggressive"):
            self.assertIn(p, self.js)

    def test_three_unattended_behaviours_are_offered(self):
        for b in ("decide", "skip", "pause"):
            self.assertIn(b, self.js)

    def test_budget_defaults_match_the_spec(self):
        self.assertIn("7200", self.js)
        self.assertIn("500000", self.js.replace("_", ""))
        self.assertRegex(self.js, r"campaign_interval[^\n]*15")

    def test_hard_block_list_is_displayed(self):
        for item in ("kill", "unpersist", "reconfig"):
            self.assertIn(item, self.js)
        self.assertRegex(self.js.lower(), r"unumkehrbar|nicht konfigurierbar")

    def test_wifi_phases_are_gated_on_capability(self):
        self.assertIn("wifi:monitor", self.js)

    def test_empty_scope_is_refused_client_side(self):
        self.assertRegex(self.js.lower(), r"scope[^\n]*(leer|required|pflicht)")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_c2_agent_gui -v`
Expected: FAIL — die Formularabschnitte fehlen

- [ ] **Step 3: Implement the form in `agent.js`**

Aufbau nach Spec §17.2, als Dialog über das bestehende `openPanel()`-Muster. Die acht Abschnitte in der Reihenfolge der Tabelle.

Festlegungen, die Tests und Spec nicht hergeben:

- **Phasen 6–8** sind nur anwählbar, wenn mindestens ein ausgewählter Beacon `wifi:monitor` meldet. Andernfalls ausgegraut mit dem Grund als `title` — genau wie im Mockup, wo „kein monitor-fähiger Adapter erkannt (onboard brcmfmac)" steht.
- **Phase 5** ist zusätzlich gesperrt, wenn die Fähigkeitsstufe aus `/api/ai/status` nicht `full` ist. Der Tooltip nennt Modell und Stufe.
- **Das Risikoprofil setzt die drei Zahlenfelder**, überschreibt sie aber nur, solange der Operator sie nicht selbst angefasst hat (ein `dirty`-Merker pro Feld).
- **Scope-Eingabe** als Tag-Liste mit Validierung gegen `ipaddress`-äquivalente Regex im Browser; ungültige CIDR werden rot markiert und blockieren das Absenden. Serverseitig prüft Task 7 erneut — die Browser-Prüfung ist Bequemlichkeit, nicht Sicherheit.
- **Presets** werden in `localStorage` gehalten. Kein Server-Zustand, weil ein Preset Operator-Vorliebe ist und kein Engagement-Artefakt.
- Der Knopf heißt **„⚡ Entfesseln"** und verlangt eine Bestätigung, die die Zahl der Ziel-Beacons und den Scope nennt.

- [ ] **Step 4: Run the tests to verify they pass, then verify in the browser**

Run: `python -m unittest software.tests.test_c2_agent_gui -v`
Expected: PASS

Dann manuell:
- Formular öffnet, Beacon-Liste zeigt die Flotte mit Capabilities
- Wifi-Phasen sind ausgegraut und nennen den Grund
- Phase 5 ist aus und muss bewusst eingeschaltet werden
- Profilwechsel setzt die Zahlen, eine selbst geänderte Zahl bleibt stehen
- Leerer Scope verhindert das Absenden
- Ungültiges CIDR wird markiert
- Preset speichern, Formular schließen, öffnen, Preset laden
- Start erzeugt eine Kampagne, der Drawer erscheint

- [ ] **Step 5: Commit**

```bash
git add software/c2/static/agent.js software/c2/static/agent.css software/tests/test_c2_agent_gui.py
git commit -m "feat(gui): add the full automated attack configuration form"
```

---

### Task 17: Scheduler

**Files:**
- Create: `software/agent/scheduler.py`
- Modify: `software/agent/service.py` (Start der Poll-Schleife, Schedule-Endpunkte)
- Test: `software/tests/test_agent_scheduler.py`

**Interfaces:**
- Consumes: `CampaignManager` (Task 13); `queries` für `scheduled_tasks` (Task 1); `notifications.get_notifier` aus `software/notifications.py`
- Produces:
  - `scheduler.validate_cron(expr) -> Optional[str]`
  - `scheduler.next_occurrence(expr) -> str` — RFC3339 in UTC
  - `queries.create_schedule(conn, prompt, config_json, schedule) -> str`
  - `queries.list_schedules(conn)`, `delete_schedule`, `pause_schedule`, `resume_schedule`
  - `queries.get_due_schedules(conn)`, `queries.advance_schedule(conn, sid, last_result)`
  - `queries.set_schedule_running(conn, sid, run_id_or_none)`
  - `await scheduler.poll_once(conn, manager, cfg) -> List[str]` — gestartete Schedule-IDs
  - `scheduler.start_loop(conn, manager, cfg) -> asyncio.Task`
  - Endpunkte `GET|POST /schedules`, `DELETE /schedules/<id>`, `POST /schedules/<id>/pause|resume`

- [ ] **Step 1: Write the failing tests**

```python
class TestCron(unittest.TestCase):
    def test_valid_five_field_expression_accepted(self):
        self.assertIsNone(scheduler.validate_cron("0 2 * * *"))

    def test_invalid_expression_returns_a_reason(self):
        self.assertIsNotNone(scheduler.validate_cron("nicht cron"))

    def test_next_occurrence_is_in_the_future(self):
        nxt = scheduler.next_occurrence("*/5 * * * *")
        self.assertGreater(nxt, datetime.now(timezone.utc).isoformat())

class TestScheduleCrud(unittest.TestCase):
    def test_create_and_list(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "scan the dmz", "{}", "0 2 * * *")
        self.assertEqual([s["id"] for s in queries.list_schedules(conn)], [sid])

    def test_pause_excludes_from_due(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        queries.pause_schedule(conn, sid)
        self.assertEqual(queries.get_due_schedules(conn), [])

    def test_resume_recomputes_next_run(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "0 2 * * *")
        queries.pause_schedule(conn, sid)
        queries.resume_schedule(conn, sid)
        s = queries.list_schedules(conn)[0]
        self.assertEqual(s["status"], "active")
        self.assertGreater(s["next_run"], datetime.now(timezone.utc).isoformat())

    def test_advance_moves_next_run_forward_and_stores_result(self):
        conn = _conn()
        sid = queries.create_schedule(conn, "p", "{}", "*/5 * * * *")
        before = queries.list_schedules(conn)[0]["next_run"]
        queries.advance_schedule(conn, sid, "12 Funde")
        after = queries.list_schedules(conn)[0]
        self.assertGreater(after["next_run"], before)
        self.assertEqual(after["last_result"], "12 Funde")

class TestPolling(IsolatedAsyncioTestCase):
    async def test_due_schedule_starts_a_campaign(self):
        conn, mgr = _conn(), _manager()
        sid = queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        self.assertEqual(await scheduler.poll_once(conn, mgr, _cfg()), [sid])
        self.assertEqual(len(mgr.started), 1)

    async def test_future_schedule_is_not_started(self):
        conn, mgr = _conn(), _manager()
        queries.create_schedule(conn, "p", _cfg_json(), "0 2 * * *")
        self.assertEqual(await scheduler.poll_once(conn, mgr, _cfg()), [])

    async def test_overlap_guard_skips_a_still_running_schedule(self):
        conn, mgr = _conn(), _manager()
        sid = queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        queries.set_schedule_running(conn, sid, 42)
        mgr.running_run_ids = {42}
        self.assertEqual(await scheduler.poll_once(conn, mgr, _cfg()), [])

    async def test_overlap_guard_clears_when_the_run_has_finished(self):
        conn, mgr = _conn(), _manager()
        sid = queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        queries.set_schedule_running(conn, sid, 42)
        mgr.running_run_ids = set()
        self.assertEqual(await scheduler.poll_once(conn, mgr, _cfg()), [sid])

    async def test_a_failing_start_still_advances_next_run(self):
        conn, mgr = _conn(), _manager(fail=True)
        sid = queries.create_schedule(conn, "p", _cfg_json(), "*/5 * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        before = queries.list_schedules(conn)[0]["next_run"]
        await scheduler.poll_once(conn, mgr, _cfg())
        after = queries.list_schedules(conn)[0]
        self.assertGreater(after["next_run"], before)
        self.assertIn("ERROR", after["last_result"])

    async def test_poll_does_not_raise_when_no_provider_is_configured(self):
        conn, mgr = _conn(), _manager()
        queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        self.assertIsInstance(
            await scheduler.poll_once(conn, mgr, _cfg(provider=None)), list)

class TestNotification(IsolatedAsyncioTestCase):
    async def test_completed_schedule_pushes_a_notification(self):
        conn, mgr = _conn(), _manager()
        sid = queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        with _fake_notifier() as sent:
            await scheduler.poll_once(conn, mgr, _cfg())
            await mgr.finish_all()
        self.assertTrue(sent)

    async def test_missing_notifier_is_not_an_error(self):
        conn, mgr = _conn(), _manager()
        queries.create_schedule(conn, "p", _cfg_json(), "* * * * *")
        conn.execute("UPDATE scheduled_tasks SET next_run = ?", (_past(),))
        with _no_notifier():
            await scheduler.poll_once(conn, mgr, _cfg())
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_scheduler -v`
Expected: FAIL mit `AttributeError`/`ModuleNotFoundError`

- [ ] **Step 3: Implement the schedule queries in `store/queries.py`**

`create_schedule` erzeugt eine UUID4 als ID und berechnet `next_run` aus dem Ausdruck. `get_due_schedules` liefert `status = 'active' AND next_run <= <jetzt>`. `advance_schedule` setzt `last_run`, `last_result` (auf 200 Zeichen gekürzt) und das neue `next_run`. `set_schedule_running` schreibt `running_run_id` oder `NULL`.

- [ ] **Step 4: Implement `software/agent/scheduler.py`**

`croniter` für Parsen und Fortschreiben, fünf Felder, UTC, `get_next` strikt in der Zukunft.

`poll_once` liest die fälligen Einträge und prüft je Eintrag die **Überlappungssperre**: ist `running_run_id` gesetzt und dieser Lauf noch in `manager.running_run_ids`, wird übersprungen (Spec §11). Sonst Kampagne aus `config_json` starten, `set_schedule_running` setzen, und einen Abschluss-Callback registrieren, der `advance_schedule` ruft, `running_run_id` löscht und über `notifications.get_notifier()` eine Meldung schickt.

**`next_run` wird immer fortgeschrieben**, auch wenn der Start fehlschlägt — sonst würde ein dauerhaft fehlschlagender Eintrag die Poll-Schleife bei jedem Durchlauf beschäftigen. Bei Fehlschlag steht `ERROR: …` im `last_result`.

Fehlt ein Notifier oder ist er abgeschaltet, wird das ignoriert — `notifications.py` ist optional konfiguriert (`configs/raccoon.yaml:157`).

`start_loop` ist ein `asyncio.Task` mit 60-Sekunden-Takt, der jede Ausnahme aus `poll_once` loggt und weiterläuft.

- [ ] **Step 5: Wire the endpoints and the loop into `service.py`**

`GET|POST /schedules`, `DELETE /schedules/<id>`, `POST /schedules/<id>/pause|resume`. Ein ungültiger Cron-Ausdruck ist `400` mit dem Grund. `start_loop` wird in `on_startup` gestartet und in `on_cleanup` abgebrochen.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_scheduler -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add software/agent/scheduler.py software/agent/service.py software/agent/store/queries.py software/tests/test_agent_scheduler.py
git commit -m "feat(agent): add cron scheduler with overlap guard and webhook notifications"
```

---

### Task 18: Auslieferung

**Files:**
- Create: `software/agent/Dockerfile`, `software/agent/requirements.txt`
- Modify: `docker-compose.yml`, `software/c2/Dockerfile`, `software/c2/start_server.sh`, `software/main.py`
- Test: `software/tests/test_agent_deployment.py`

**Interfaces:**
- Consumes: `software/agent/__main__.py` (Task 14)
- Produces: Service `agent` in `docker-compose.yml`, Umgebungsvariablen `AGENT_URL`, `RACCOON_AGENT_TOKEN`, `RACCOON_TOKEN`

- [ ] **Step 1: Write the failing tests**

```python
class TestAgentImage(unittest.TestCase):
    def setUp(self):
        self.df = Path("software/agent/Dockerfile").read_text()
        self.reqs = Path("software/agent/requirements.txt").read_text()

    def test_requirements_are_the_agent_set_only(self):
        for pkg in ("aiohttp", "anthropic", "openai", "PyYAML", "croniter"):
            self.assertIn(pkg.lower(), self.reqs.lower())

    def test_agent_image_has_no_offensive_arsenal(self):
        """Spec §18: schlankes Image, das Arsenal wird über die C2-API gerufen."""
        for pkg in ("impacket", "lsassy", "netexec", "nmap", "responder"):
            self.assertNotIn(pkg, self.df.lower())

    def test_agent_image_copies_the_agent_package(self):
        self.assertIn("software/agent", self.df)

    def test_agent_image_runs_the_module(self):
        self.assertRegex(self.df, r"software\.agent|-m\s+software\.agent")

class TestC2Image(unittest.TestCase):
    def test_c2_image_does_not_install_llm_sdks(self):
        """Spec §19.5: der C2 braucht anthropic/openai/aiohttp nicht."""
        df = Path("software/c2/Dockerfile").read_text().lower()
        for pkg in ("anthropic", "openai", "aiohttp", "croniter"):
            self.assertNotIn(pkg, df)

class TestCompose(unittest.TestCase):
    def setUp(self):
        self.compose = yaml.safe_load(Path("docker-compose.yml").read_text())

    def test_agent_service_exists(self):
        self.assertIn("agent", self.compose["services"])

    def test_agent_publishes_no_ports(self):
        self.assertFalse(self.compose["services"]["agent"].get("ports"))

    def test_agent_shares_the_host_network(self):
        """network_mode: host beim C2 — es gibt kein Compose-Netz."""
        self.assertEqual(self.compose["services"]["agent"].get("network_mode"), "host")

    def test_neither_service_depends_on_the_other(self):
        """Spec §19.1: keiner wartet auf den anderen."""
        for name in ("raccoon-c2", "agent"):
            self.assertFalse(self.compose["services"][name].get("depends_on"))

    def test_c2_receives_the_agent_url(self):
        env = _env_map(self.compose["services"]["raccoon-c2"])
        self.assertIn("AGENT_URL", env)
        self.assertIn("127.0.0.1", env["AGENT_URL"])
        self.assertIn("8099", env["AGENT_URL"])

    def test_both_services_share_the_agent_token_variable(self):
        for name in ("raccoon-c2", "agent"):
            self.assertIn("RACCOON_AGENT_TOKEN", _env_map(self.compose["services"][name]))

    def test_api_keys_are_not_literals_in_compose(self):
        raw = Path("docker-compose.yml").read_text()
        self.assertNotRegex(raw, r"(sk-|sk-ant-)[A-Za-z0-9]{10}")

class TestSliverWarning(unittest.TestCase):
    def test_main_warns_when_sliver_and_agent_are_both_configured(self):
        cfg = {"c2": {"sliver": {"enabled": True}}, "agent": {"enabled": True}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertRegex("\n".join(logs).lower(), r"sliver")

    def test_no_warning_without_an_agent_block(self):
        """Status quo: ausgelieferte Vorbelegung bleibt still."""
        cfg = {"c2": {"sliver": {"enabled": True}}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertEqual(logs, [])

    def test_no_warning_when_sliver_is_off(self):
        cfg = {"c2": {"sliver": {"enabled": False}}, "agent": {"enabled": True}}
        with _capture_logs() as logs:
            main._check_agent_beacon_conflict(cfg)
        self.assertEqual(logs, [])

class TestLauncher(unittest.TestCase):
    def test_start_server_can_launch_the_agent_optionally(self):
        sh = Path("software/c2/start_server.sh").read_text()
        self.assertIn("software.agent", sh)
        self.assertRegex(sh, r"AGENT|agent")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m unittest software.tests.test_agent_deployment -v`
Expected: FAIL — `software/agent/Dockerfile` fehlt

- [ ] **Step 3: Create `software/agent/requirements.txt` and `Dockerfile`**

`requirements.txt`: `aiohttp`, `anthropic`, `openai`, `PyYAML`, `croniter`. Nichts weiter — SQLite ist Standardbibliothek.

Das Dockerfile basiert auf `python:3.12-slim`, installiert die Requirements, kopiert `software/agent/` und `software/notifications.py` (für den Push-Kanal) und startet `python -m software.agent`. **Build-Kontext ist das Repo-Root** — das bestehende `software/c2/Dockerfile` hat `software/c2/` als Kontext und könnte `software/agent/` nicht sehen (Spec §18).

- [ ] **Step 4: Add the `agent` service to `docker-compose.yml`**

`build: {context: ., dockerfile: software/agent/Dockerfile}`, `network_mode: host`, keine `ports`, kein `depends_on` in beide Richtungen. Volume für die Agent-DB. Umgebungsvariablen: `AGENT_BIND_HOST=127.0.0.1`, `AGENT_BIND_PORT=8099`, `RACCOON_C2_URL`, `RACCOON_TOKEN`, `RACCOON_AGENT_TOKEN`, `AGENT_PROVIDER`, `AGENT_MODEL`, `AGENT_API_KEY` — alle als `${VAR}`-Verweise ohne Literale.

Der `raccoon-c2`-Service bekommt zusätzlich `AGENT_URL=http://127.0.0.1:8099` und `RACCOON_AGENT_TOKEN`.

Im Kommentarblock festhalten, dass `RACCOON_TOKEN` **fest vorgegeben** sein muss, wenn der Agent genutzt wird — sonst erzeugt der C2 beim Start einen Zufallstoken, den der Agent nicht kennt (Spec §18).

- [ ] **Step 5: Add `_check_agent_beacon_conflict` to `software/main.py`**

Prüft, ob `agent.enabled` **und** `c2.sliver.enabled` beide gesetzt sind, und protokolliert dann eine Warnung, dass eine Sliver-verwaltete Box beim Team-Server nie eincheckt und für den Agenten unsichtbar bleibt. Aufruf beim Start, nach dem Laden der Konfiguration.

**Keine Verhaltensänderung** — nur eine Warnung. Ohne `agent:`-Block bleibt alles wie heute (Spec §5.2).

- [ ] **Step 6: Extend `software/c2/start_server.sh` and the C2 Dockerfile**

Im Launcher eine optionale Frage, ob der Agent-Dienst mitgestartet werden soll; bei Ja wird `python -m software.agent` im Hintergrund gestartet und `AGENT_URL` exportiert. Im C2-Dockerfile die COPY-Liste um nichts erweitern — der Agent hat sein eigenes Image. **Die LLM-SDKs werden dem C2-Image nicht hinzugefügt.**

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m unittest software.tests.test_agent_deployment -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add software/agent/Dockerfile software/agent/requirements.txt docker-compose.yml software/c2/start_server.sh software/main.py software/tests/test_agent_deployment.py
git commit -m "chore(agent): add deployment for the agent service as an optional sidecar"
```

---

### Task 19: Status quo und Ende-zu-Ende

**Files:**
- Create: `software/tests/test_status_quo.py`, `software/tests/test_agent_e2e.py`
- Test: beide oben

**Interfaces:**
- Consumes: alles aus Tasks 1–18
- Produces: nichts — das ist die Abnahme

Diese Testgruppe ist die Absicherung von Ziel 7 und darf **kein** Modul aus `software/agent/` benötigen, um zu laufen.

- [ ] **Step 1: Write the status quo suite**

```python
class TestExistingSuiteUnaffected(unittest.TestCase):
    def test_full_existing_suite_passes(self):
        """Fängt Regressionen, die Einzeltests durchlassen."""
        r = subprocess.run(
            [sys.executable, "-m", "unittest",
             "software.tests.test_c2_server", "software.tests.test_beacon",
             "software.tests.test_sniffer", "software.tests.test_nac_bypass"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-4000:])

class TestC2WithoutAgentPackage(unittest.TestCase):
    def test_server_imports_without_the_agent_package(self):
        """Spec §19.5: keine Kopplung über Importe."""
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.modules['software.agent'] = None;"
             " import software.c2.server as s; print(s.__name__)"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])

    def test_server_source_has_no_agent_import(self):
        src = Path("software/c2/server.py").read_text()
        self.assertNotIn("software.agent", src)

    def test_server_needs_no_llm_sdk(self):
        src = Path("software/c2/server.py").read_text()
        for mod in ("anthropic", "openai", "aiohttp", "croniter"):
            self.assertNotIn(f"import {mod}", src)

class TestC2WithoutAgentService(ServerTestBase):
    def test_index_renders(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_agent_list_works(self):
        self.assertIsInstance(self._operator_get("/api/agents"), list)

    def test_full_task_roundtrip_works(self):
        _reset_server_state()
        self._register_agent()
        t = self._operator_post("/api/agents/raccoon-a/task", {"cmd": "whoami"})
        self.assertEqual(self._checkin("raccoon-a")["cmd"], "whoami")
        self._post_result("raccoon-a", t["id"], "ok", "root")
        self.assertEqual(self._operator_get(f"/api/tasks/{t['id']}")["output"], "root")

    def test_ai_routes_return_503_not_500(self):
        for path in ("/api/ai/status", "/api/ai/beacons"):
            self.assertEqual(self._operator_get_raw(path).status_code, 503, path)

    def test_server_log_and_loot_endpoints_work(self):
        self.assertIsInstance(self._operator_get("/api/logs/server"), list)
        self.assertIsInstance(self._operator_get("/api/loot"), list)

class TestBeaconCompatibilityBothWays(unittest.TestCase):
    def test_old_beacon_payload_registers(self):
        """Register-Payload ohne caps."""
        _reset_server_state()
        resp = _beacon_post_raw({"action": "register", "id": "abc", "hostname": "h",
                                 "os": "Linux 6.1", "arch": "x86_64", "pid": 1,
                                 "user": "u", "interval": 300})
        self.assertTrue(resp["success"])

    def test_new_beacon_payload_against_a_server_ignoring_caps(self):
        info = _beacon()._system_info()
        self.assertIn("caps", info)
        stripped = {k: v for k, v in info.items() if k != "caps"}
        self.assertTrue(_handle_register_accepts(stripped))

    def test_unknown_command_still_returns_the_existing_error(self):
        b = _beacon()
        out = b._process_tasking({"cmd": "wire", "args": "summary", "task_id": "t1"})
        self.assertIn("Unknown command", _last_result_output(b))

class TestDropBoxDefaults(unittest.TestCase):
    def test_shipped_config_still_prefers_sliver(self):
        cfg = yaml.safe_load(Path("configs/raccoon.yaml").read_text())
        self.assertTrue(cfg["c2"]["sliver"]["enabled"])

    def test_shipped_config_has_the_agent_block_disabled(self):
        cfg = yaml.safe_load(Path("configs/raccoon.yaml").read_text())
        self.assertFalse(cfg["agent"]["enabled"])
```

- [ ] **Step 2: Run the status quo suite**

Run: `python -m unittest software.tests.test_status_quo -v`
Expected: PASS

- [ ] **Step 3: Write the end-to-end suite**

```python
class TestCampaignEndToEnd(IsolatedAsyncioTestCase):
    """Echter C2 + echter Beacon + Mock-Modell."""
    async def test_campaign_drives_a_live_beacon(self):
        env = await _live_env()          # C2 auf Port, Beacon verbunden, Agent-Store
        client = mock.MockClient([
            mock.calls(("set_phase", {"phase": 1})),
            mock.calls(("dispatch_task", {"task_name": "whoami",
                                          "task_description": "wer bin ich"})),
            mock.calls(("remember_finding", {"host": "127.0.0.1",
                                             "finding_type": "note",
                                             "data": "läuft als root"})),
            mock.calls(("log_score", {"action": "host_discovered"})),
            mock.text("Kampagne abgeschlossen: 1 Host"),
            mock.calls(("run_command", {"command": "whoami",
                                        "beacon_id": env.beacon_id})),
            mock.text("TASK: whoami\nSTATUS: success\nFINDINGS:\n  - root")])
        camp = _campaign(env, client)
        rid = await camp.start()
        report = await asyncio.wait_for(camp.wait(), timeout=120)

        run = queries.get_run(env.conn, rid)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["phase"], 1)
        self.assertEqual(
            env.conn.execute("SELECT status FROM tasks").fetchone()["status"],
            "completed")
        self.assertEqual(len(queries.get_findings_by_host(env.conn, "127.0.0.1")), 1)
        self.assertEqual(queries.get_score_context(env.conn, rid)["total_score"], 10)
        self.assertIn("abgeschlossen", report)

    async def test_interval_is_restored_after_the_campaign(self):
        env = await _live_env()
        camp = _campaign(env, mock.MockClient([mock.text("fertig")]))
        await camp.start(); await camp.wait()
        agent = await env.c2.get_agent(env.beacon_id)
        self.assertEqual(agent["interval"], 300)

    async def test_operator_task_overtakes_a_queued_agent_plan(self):
        """Anti-Ziel: der Operator darf nicht warten."""
        env = await _live_env()
        for i in range(5):
            await env.c2.queue_task(env.beacon_id, "pwd", lane="agent")
        tid = await env.c2.queue_task(env.beacon_id, "whoami", lane="operator")
        res = await env.c2.await_task(tid, timeout=90)
        self.assertTrue(res)

    async def test_out_of_scope_target_never_reaches_the_beacon(self):
        env = await _live_env(scope_allow=["10.99.0.0/24"])
        camp = _campaign(env, mock.MockClient([
            mock.calls(("dispatch_task", {"task_name": "t",
                                          "task_description": "d"})),
            mock.text("abgelehnt verstanden"),
            mock.calls(("run_command", {"command": "netscan 192.168.50.0/24",
                                        "beacon_id": env.beacon_id})),
            mock.text("TASK: t\nSTATUS: failed")]))
        await camp.start(); await camp.wait()
        history = await env.c2_raw_history(env.beacon_id)
        self.assertNotIn("192.168.50", json.dumps(history))
```

- [ ] **Step 4: Run the end-to-end suite**

Run: `python -m unittest software.tests.test_agent_e2e -v`
Expected: PASS

- [ ] **Step 5: Run everything**

Run: `python -m unittest discover -s software/tests -v`
Expected: PASS, keine Fehler, keine Skips außer den ausdrücklich als Mock-only markierten

- [ ] **Step 6: Commit**

```bash
git add software/tests/test_status_quo.py software/tests/test_agent_e2e.py
git commit -m "test: add status quo guarantees and end-to-end campaign coverage"
```

---

## Nach diesem Plan

Die beiden Teilprojekte aus der Spec sind eigene Pläne und werden **nach** diesem geschrieben, gegen die hier entstandenen Interfaces statt gegen geratene:

- **Wire Intel** (Spec §15) — `wire`-Kommandos im Beacon, `wire_intel`-Tabelle, `get_wire_intel`-Tool, Wire-Preamble. Hängt an `_detect_caps` (Task 10) und `registry`-Capability-Filterung (Task 12).
- **Wifi-Kette** (Spec §16) — Adaptererkennung, Monitor-Mode-Kontextmanager, sechs Beacon-Kommandos, vier Wifi-Tabellen, sechs Tools, Wifi-Orchestrator-Preamble, Pakete im Box-Image. Hängt an denselben zwei Stellen plus der Deauth-Governance in `safety.py` (Task 2).

Beide liefern für sich lauffähige, testbare Software: ohne sie läuft die Agenten-Schicht vollständig, nur ohne passive Draht-Aufklärung und ohne WLAN.









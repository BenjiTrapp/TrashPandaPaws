# Autonomer Angriffs-Agent für Raccoon C2

**Status:** Entwurf zur Freigabe
**Datum:** 2026-10-30
**Betrifft:** `software/agent/` (neu), `software/c2/server.py` (Proxy, Lanes, Batching, Tool-Läufe), `software/c2/beacon.py` (Capabilities, Batching, `wire`- und `wifi`-Kommandos), `software/main.py` + `configs/raccoon.yaml` (Beacon-Wahl auf der Drop-Box)

---

## 1. Absicht und Begründung

Der Raccoon C2 kann heute alles, was ein Operator braucht — aber nur, wenn ein Operator davor sitzt und tippt. Jede Phase einer Enumeration, jedes `netscan`, jedes Nachfassen auf einen Fund ist Handarbeit.

Dieses Dokument beschreibt eine autonome Agenten-Schicht, die diese Handarbeit übernimmt: ein LLM plant eine mehrphasige Kampagne, zerlegt sie in Aufgaben, führt sie über die bestehenden Beacons und das serverseitige Werkzeugarsenal aus, bewertet die Funde und entscheidet selbst, was als Nächstes sinnvoll ist. Der Operator bekommt dafür zwei neue Betriebsarten:

- **Automated Attack** — der Agent arbeitet, der Operator sieht zu und greift parallel selbst ein
- **Full Automated** — vorkonfiguriert, dann ohne Aufsicht

Die Vorlage ist [Eugene](https://codeberg.org/Haaari/eugene), ein autonomer Offensive-Agent in Rust auf Basis von `rig-core`. Dieses Projekt ist eine **Neuimplementierung in Python**, keine Portierung: Eugenes Architektur, Prompt-Struktur, Scoring-Modell und Safety-Philosophie werden übernommen, der Code nicht.

### Warum die Kombination mehr ist als die Summe

Eugene hat eine strukturelle Schwäche: er führt alles **lokal** aus. Das README beschreibt einen „split mode", in dem Eugene außerhalb des Zielnetzes läuft und per SSH auf eine nackte Kali-Pi zugreift — **dieser Code existiert nicht**. `LocalExecutor` ist `tokio::process` auf der Maschine, auf der Eugene läuft, und das Architekturdiagramm mit dem SSH-Knoten ist Wunschdenken.

Genau dieses Loch füllt der Raccoon C2. Er hat bereits, was Eugene fehlt:

| Eugene braucht | Raccoon C2 hat |
|---|---|
| Ausführung auf fremden Hosts | Multi-Transport-Beacons (HTTPS/DNS/SMB/QUIC) mit AES-GCM |
| Einen Weg ins Zielnetz | Inline-Bridge mit NAC-Bypass und Cover-Identität |
| Werkzeuge gegen das Netz | 16 Impacket-Tools, NetExec, Responder, RelayKing, SMBLoot |
| Passive Aufklärung | Sniffer im Datenpfad mit Credential-/HTTP-/DNS-Filtern |
| Operator-Oberfläche | Vollständiges Web-GUI mit Agent-Verwaltung |

Umgekehrt hat der C2 kein Gehirn. Die Kombination ist also keine Feature-Addition, sondern das Zusammenführen zweier Hälften.

### Umfang: volle Ausbaustufe

Entschieden wurde die **volle** Ausbaustufe. Das sind drei Teilprojekte, nicht eins:

1. **Die Agenten-Schicht** (Abschnitte 7–14) — gegen die bereits existierende Ausführungsfläche.
2. **Wire Intel** (Abschnitt 15) — neue `wire`-Kommandos im Beacon, die den Bridge-Mitschnitt auswertbar machen. Existiert heute nicht.
3. **Die Wifi-Kette** (Abschnitt 16) — Adaptererkennung und Angriffskommandos im Beacon. Existiert heute nicht.

Teil 1 ist ein Aufsatz auf Bestehendes. Teile 2 und 3 sind neue Ausführungsfläche auf der Drop-Box und als eigene Arbeitspakete zu behandeln.

---

## 2. Ziele

1. Eine mehrphasige Enumeration läuft ohne Operator-Eingaben von „Beacon eingecheckt" bis „Bericht liegt vor".
2. Der Operator kann während einer laufenden Kampagne **jederzeit selbst Kommandos absetzen**, ohne auf den Agenten zu warten.
3. Jede Agent-Aktion, jede LLM-Antwort und jede Entscheidung ist revisionssicher nachvollziehbar.
4. Der Agent kann die Operation nicht versehentlich zerstören — Verbindungsverlust und Enttarnung sind die beiden Risiken, gegen die abgesichert wird.
5. Vier LLM-Anbieter werden unterstützt, inklusive lokaler Modelle beim Operator.
6. Der Agent nutzt **dieselbe HTTP-API wie der Operator**. Seine Aktionen erscheinen damit automatisch in der bestehenden History, dem bestehenden Server-Log und der bestehenden Loot-Vault.
7. **Ohne angebundenes LLM funktioniert der C2 unverändert weiter.** Die Agenten-Schicht ist durchgängig optional — kein konfigurierter Anbieter, kein laufender Agent-Dienst und kein API-Key dürfen den Status quo beeinträchtigen. Siehe Abschnitt 19.

## 3. Nicht-Ziele

- **Kein Ersatz des Operator-GUI.** Der Agent ist ein Modus darin, keine zweite Oberfläche.
- **Kein Telegram-Bot.** Eugenes C2-Kanal entfällt; das GUI ist die Steuerung, `notifications.py` (Slack/Discord/Teams, bereits vorhanden) ist der Push-Kanal.
- **Keine Änderung des Beacon-Transports.** HTTPS/DNS/SMB/QUIC, Crypto und Malleable-Profile bleiben unangetastet.
- **Keine automatische Ausweitung des Scopes.** Der Agent findet Hosts, aber greift nur innerhalb der freigegebenen CIDRs an.
- **Kein Agent auf der Drop-Box.** Das Gehirn läuft beim Operator. Auf der Box liegen keine API-Keys und keine LLM-Datenbank.
- **Kein zweiter Executor-Pfad über Sliver.** Siehe Abschnitt 5.2.

## 4. Anti-Ziele

Dinge, die dieses Projekt zum Scheitern bringen würden, auch wenn es technisch funktioniert:

- **Ein Agent, der den Beacon verliert.** Ein autonomer Lauf, der mit einer toten Drop-Box endet, ist schlimmer als kein autonomer Lauf. Deshalb sind unumkehrbare Aktionen hart blockiert statt bewertet.
- **Ein Agent, der die Operation enttarnt.** Ein Lauf, der ein `-T5`-Scan über ein Kundennetz legt und das SOC aufweckt, kostet die Engagement-Glaubwürdigkeit.
- **Ein Operator, der warten muss.** Wenn ein manuelles Kommando hinter einem 20-Schritt-Agentenplan in der Queue hängt, ist der Modus unbenutzbar.
- **Ein blockierter C2.** Wenn ein LLM-Timeout oder eine Exception in der Agenten-Schicht das Beacon-Handling anhält, ist das Fleet-Management kaputt.
- **Ein Protokoll, das man nicht lesen kann.** „Der Agent hat irgendwas gemacht" ist für einen Pentest-Bericht wertlos.
- **Eine Leine, die mit drei Zeilen Python umgehbar ist.** Siehe Abschnitt 10.2 zu `run_script`.
- **Ein C2, der ein LLM braucht, um zu funktionieren.** Wer den Agenten nicht nutzt, darf von diesem Projekt nichts merken — kein fehlender API-Key, kein kaputtes GUI, kein geänderter Beacon, kein zusätzlicher Pflicht-Dienst.

## 5. Randbedingungen

### 5.1 Aus dem bestehenden Code

| Befund | Fundstelle | Folge für den Entwurf |
|---|---|---|
| Ein Task pro Check-in (`queue.pop(0)`) | `server.py:1855-1857` | Ein 20-Schritt-Plan braucht bei `interval=300` über 90 Minuten. Erfordert Intervall-Absenkung **und** Task-Batching. |
| Keine Datenbank, nur globale Dicts + `state.json` | `server.py:114-125`, `177-184` | Der Agent bringt sein eigenes SQLite mit. `event_log` ist nicht revisionssicher (In-Memory, bei 5000 Einträgen rotierend, nicht persistiert). |
| `server_exec_state` ist ein einziger globaler Slot | `server.py:481` | Parallele serverseitige Tool-Läufe überschreiben sich. Muss auf einen `run_id`-Dict umgestellt werden. |
| `/api/server/exec` nutzt `shell=True`, Timeout fest 300 s, Ausgabe bei Timeout verworfen | `server.py:482-520` | Widerspricht der argv-Regel und killt lange `-T2`-Scans. Beides muss geändert werden (Abschnitt 9.3). |
| `task["status"]="dispatched"` ist ein toter Schreibvorgang | `server.py:1858` | Nach dem `pop` referenziert nichts mehr das Dict. Fertigstellung ist nur über `history` erkennbar. |
| Werkzeug-Dev-Server mit `threaded=True`, keine Locks | `server.py:7413` | Spricht gegen eine asyncio-Schleife im selben Prozess. |
| Operator-GUI ist ein 5.388-zeiliges String-Literal | `server.py:1930-7317` | GUI-Arbeit ist unangenehm, aber `/static/<path>` existiert bereits als Ausweg. |
| Ein einziges Credential, Vergleich per `==` | `server.py:265-269` | Kein `hmac.compare_digest`. Der Agent braucht ein eigenes Token (Abschnitt 18). |
| `GET /` liefert den Operator-Token unauthentifiziert aus | `server.py:299` | Der Agent-Token darf diesen Weg nicht gehen. |
| `docker-compose.yml` nutzt `network_mode: host` | `docker-compose.yml` | Es gibt kein Compose-Netz für Service-Namen. Der Agent bindet auf Loopback (Abschnitt 18). |
| Dockerfile-Build-Kontext ist `software/c2/`, kopiert drei flache Dateien | `Dockerfile:39-41` | `software/agent/` liegt außerhalb. Zweites Dockerfile mit Repo-Root-Kontext nötig. |
| Tests: stdlib `unittest`, kein pytest, kein CI | `software/tests/` | Konvention wird beibehalten. |
| Python 3.9.6 in den venvs, 3.12 im Docker-Image | `Dockerfile`, `.venv` | **Zielversion 3.9.** Kein `match`, kein `X \| Y` zur Laufzeit, kein `asyncio.TaskGroup`, kein `tomllib`. |
| FTS5 im System-sqlite3 vorhanden (geprüft) | — | Trotzdem Rückfall auf `LIKE` statt Startverweigerung. |

### 5.2 Die Drop-Box fährt den Python-Beacon

**Entschieden.** `software/main.py:111-147` bevorzugt heute das Sliver-Implant und fällt nur auf `software/c2/beacon.py` zurück, wenn die Binary fehlt; `configs/raccoon.yaml:77` liefert `sliver.enabled: true` aus. `server.py` enthält **keine Referenz auf Sliver** — eine Sliver-verwaltete Box checkt beim Team-Server nie ein und ist für den Agenten unsichtbar.

Da Wire Intel und die Wifi-Kette beide am Capability-Modell in `beacon.py` hängen, gilt:

- Für Engagements mit Agenten-Betrieb ist der **Python-Beacon die Vorgabe** auf der Box.
- **Die ausgelieferte Vorbelegung ändert sich nicht.** Ohne konfigurierten `agent:`-Block bleibt `sliver.enabled: true` und `main.py` verhält sich exakt wie heute. Die Exklusivität greift nur, wenn ein Agenten-Block vorhanden ist.
- `configs/raccoon.yaml` bekommt einen Kommentar, dass `sliver.enabled: true` und Agenten-Betrieb sich ausschließen.
- `software/main.py` protokolliert beim Start eine Warnung, wenn Sliver aktiv ist und ein Agenten-Block konfiguriert wurde.
- Sliver bleibt vollständig nutzbar — dann ist die Box eben nicht agentengesteuert.
- `beacon_standalone.py` bekommt dieselbe Capability-Meldung wie `beacon.py`.

Ein zweiter Executor-Pfad über die Sliver-API ist **explizites Nicht-Ziel**.

### 5.3 Hardware

Die Drop-Box ist ein **Raspberry Pi 4** als Inline-Ethernet-Bridge (`eth0 ↔ br0 ↔ eth1`), die sich als Cisco IP Phone 7960 oder HP LaserJet M478 ausgibt (`configs/raccoon.yaml`).

Das onboard-WLAN ist ein Broadcom CYW43455 mit `brcmfmac`. **Passives Scannen funktioniert, Monitor-Mode und Injection nicht** — ohne Nexmon-Patches kein `aireplay-ng`, kein `hcxdumptool`.

**Aktuell steht kein externer monitor-fähiger Adapter zur Verfügung.** Daraus folgt für Abschnitt 16: die Stufung wird vollständig gebaut, aber alles oberhalb von `wifi:scan` ist **nur gegen Mocks geprüft** und im Code als ungetestet gegen echte Hardware markiert.

### 5.4 Betrieb

- Ein Lauf darf Geld kosten, aber messbar: Token- und Laufzeit-Budget sind Abbruchbedingungen, keine Statistik.
- Lokale und freie Modelle haben schwaches Tool-Calling. Der Entwurf muss mit beiden Klassen umgehen (Abschnitt 13).

---

## 6. Betrachtete Ansätze

Die Frage war, wie die Agenten-Schicht am bestehenden C2 andockt.

### A — Im Team-Server-Prozess

Neues Paket `software/c2/agent/`, importiert von `server.py`, Routen innerhalb von `create_app`, Panel im bestehenden GUI-String.

*Dafür:* Kein Netzwerkcode. `crypto`, `operator_token` und `data_dir` liegen im Scope. Ein Prozess, Docker fast unverändert.
*Dagegen:* Der Server ist ein threaded Werkzeug-Dev-Server ohne Locks um seine globalen Dicts. Eine asyncio-Schleife darin bedeutet eine Thread/Event-Loop-Brücke für jeden DB-Zugriff und jeden LLM-Call. Eine unbehandelte Exception in der Agenten-Schicht nimmt das Beacon-Handling mit — direkter Verstoß gegen Anti-Ziel „blockierter C2".

### B — Eigener Dienst, spricht die C2-API direkt

Separater asyncio-Prozess, nutzt denselben Bearer-Token und dieselben Endpoints wie das GUI, eigene SQLite, eigene UI auf eigenem Port.

*Dafür:* Saubere Isolation, echtes asyncio, läuft auch off-box, standalone testbar.
*Dagegen:* Zweiter Origin im Browser — CORS-Konfiguration, zweiter Token-Pfad, zwei Oberflächen, die der Operator im Kopf zusammenhalten muss.

### C — Eigener Dienst, der C2 reicht ihn durch *(gewählt)*

Wie B, plus ein dünner Satz Proxy-Routen `/api/ai/*` in `server.py`, die an den Agenten-Dienst weiterleiten. Das GUI spricht ausschließlich mit dem C2.

*Dafür:* Isolation von B bei der Einfachheit von A. Ein Origin, ein Token, kein CORS. Der Proxy ist eine überschaubare Menge Code.
*Dagegen:* Ein Netzwerk-Hop mehr. Status muss durchgepollt werden statt direkt gelesen.

### Entscheidung

**C.** Der ausschlaggebende Grund ist die Blast-Radius-Grenze: wenn das LLM entgleist, ein Provider hängt oder die Agenten-Schicht abstürzt, läuft das Beacon-Fleet weiter. Dazu bekommt der Agent eine ordentliche asyncio-Laufzeit, statt in einem Thread-Pool neben einem synchronen WSGI-Server zu sitzen.

### Verworfen: Agent als „virtueller Operator" ohne UI

Der Agent treibt die bestehende API wie ein Mensch, Steuerung nur per CLI, Beobachtung im normalen GUI. Minimaler Code, null GUI-Arbeit — erfüllt aber die Kernanforderung „Automated-Attack-Knopf" nicht.

**Das Prinzip daraus wird übernommen:** der Agent tasked über dieselbe API wie der Operator, damit seine Aktionen ohne Zusatzarbeit in allen bestehenden Ansichten auftauchen.

---

## 7. Architektur

```
┌─────────────────────────────── Operator-Infrastruktur ───────────────────────────────┐
│                                                                                      │
│   Browser ──────► Raccoon C2 Team Server ──────► Agent-Dienst                        │
│                   software/c2/server.py          software/agent/                     │
│                   Flask, threaded                aiohttp, asyncio                    │
│                                                                                      │
│                   • Beacon-Handling              • Orchestrator-Schleife             │
│                   • Operator-API                 • Executor-Schleifen (max 4)        │
│                   • /api/ai/* ──Proxy──────────► • SQLite (Runs, Tasks, Findings,    │
│                   • Task-Lanes                     Scores, Approvals, LLM-Log)       │
│                   • Tool-Läufe           ◄───────• treibt die C2-API als Client      │
│                     (Impacket, NXC, ...)                                             │
│                                                      │                               │
│                                                      ▼                               │
│                                               LLM-Provider                           │
│                                      Anthropic · OpenRouter ·                        │
│                                      OpenCode Zen · lokal                            │
└──────────────────────────────────────────────────────────────────────────────────────┘
                              │ HTTPS / DNS / SMB / QUIC (AES-GCM)
                              ▼
┌─────────────────────────── Zielnetz ───────────────────────────┐
│   Drop-Box (Pi 4, Python-Beacon)   Beacons auf                 │
│   Bridge · NAC-Bypass · Cover      kompromittierten Hosts      │
│   Sniffer (wire) · WLAN (scan)                                 │
└────────────────────────────────────────────────────────────────┘
```

Zwei Prozesse, `docker-compose` startet beide. Nur der C2 ist exponiert.

### 7.1 Modulstruktur

```
software/agent/
├── __init__.py
├── __main__.py           # Einstiegspunkt, CLI
├── config.py             # YAML + Umgebungsvariablen, Auflösungskaskade
├── service.py            # aiohttp-App: /campaign /status /approve /pause /resume /stop
├── store/
│   ├── schema.sql        # DDL, ein Batch
│   ├── db.py             # Verbindung, Pragmas, FTS5-Probe mit LIKE-Rückfall
│   └── queries.py        # Runs, Tasks, Findings, Scores, Approvals, Memory, Scripts, LLM-Log
├── llm/
│   ├── provider.py       # create_client(), Fähigkeitsstufen
│   ├── anthropic_client.py
│   ├── openai_client.py  # OpenRouter, OpenCode Zen, Ollama, LM Studio
│   └── loop.py           # Tool-Calling-Schleife, Turn-Budget, Hooks, Text-Fallback
├── prompts.py            # Orchestrator-, Executor-, Wifi-, Wire-Preamble
├── orchestrator.py       # Kampagnen-Lebenszyklus, dispatch_task(_parallel), set_phase
├── executor/
│   ├── beacon.py         # Ausführung über die C2-API (Agent-Lane)
│   ├── server_tool.py    # Ausführung auf der C2-Box (argv)
│   └── router.py         # Zielauswahl nach Capability, Klassifikation, Gate-Aufruf
├── safety.py             # Hard-Blocks, Knock-Liste, Scope, Scan-Limits, Risikotabelle
├── gate.py               # Approval-Mechanik, EV-Schiedsrichter
├── tools/                # Ein Modul pro LLM-Tool
├── scheduler.py          # Cron-Poll-Schleife mit Überlappungssperre
└── c2client.py           # Typisierter Client für die Raccoon-API
```

### 7.2 Änderungen am bestehenden Code

Für die Agenten-Schicht sind die Eingriffe klein. Für Wire Intel und Wifi sind sie es **nicht** — das sind neue Kommandos im Beacon und neue Pakete im Image.

**Am C2-Server (`server.py`):**

1. **Proxy-Routen** `/api/ai/<path:p>` (GET/POST), `@require_auth`, leiten an `AGENT_URL` weiter. Fehlender Agent-Dienst → `503` mit klarer Meldung, keine Exception.
2. **Task-Lanes.** Das Task-Dict bekommt `lane: "operator" | "agent"`, Vorbelegung `"operator"`. `_handle_beacon` nimmt den ersten Operator-Task, sonst den ersten Agent-Task.
3. **Task-Batching.** Für Beacons mit `caps` enthält `"batch"` liefert `_handle_beacon` bis zu `N` Tasks als `{"tasks": [...]}`. Beacons ohne diese Capability bekommen unverändert ein einzelnes Task-Dict.
4. **Tool-Läufe parallelisierbar und zuordenbar.** `server_exec_state` wird zu `tool_runs: dict[run_id, state]` mit zusätzlichem Feld `origin: "operator" | "agent"`. `POST /api/server/exec` liefert eine `run_id`; `GET /api/server/exec/result/<run_id>` den Zustand. Der alte parameterlose Endpoint bleibt als Alias auf den jüngsten **Operator**-Lauf, damit Agent-Ausgaben nicht im Operator-Panel landen.
5. **argv-Form und Timeout** für `/api/server/exec` — Abschnitt 9.3.
6. **GUI-Erweiterung** — Abschnitt 17.

**Am Beacon (`beacon.py`, `beacon_standalone.py`):**

7. **Capability-Meldung** bei `register` (Abschnitt 7.3).
8. **Batch-Verarbeitung** — `{"tasks":[...]}` wird sequentiell abgearbeitet, Ergebnisse einzeln zurückgemeldet.
9. **`wire`-Kommandos** — Abschnitt 15.
10. **`wifi`-Kommandos** — Abschnitt 16.

**An der Box (`main.py`, `configs/raccoon.yaml`):** Beacon-Wahl und Warnung, Abschnitt 5.2.

**Auslieferung:** Abschnitt 18.

### 7.3 Beacon-Capabilities

Der Beacon meldet bei `register` eine Fähigkeitsliste. Das ersetzt Rateversuche im Agenten und vereinheitlicht Drop-Box und gewöhnlichen Beacon zu einem Konzept.

| Capability | Bedeutung | Erkennung |
|---|---|---|
| `batch` | versteht `{"tasks":[...]}` | statisch ab dieser Beacon-Version |
| `sniffer` | Bridge-Tap läuft, Mitschnitte vorhanden | Capture-Dir aus `raccoon.yaml` existiert und enthält pcaps |
| `wifi:scan` | WLAN-Interface vorhanden | `/sys/class/net/*/wireless` |
| `wifi:monitor` | monitor-/injection-fähiger Adapter | sysfs-Treiber-Symlink gegen `88XXau`, `rtl8812au`, `8812au` |
| `smbloot` | Pure-Python-SMB2-Stack | statisch |
| `windows` / `posix` | Plattformklasse | `platform.system()` |

Der Orchestrator-Preamble listet die Capabilities der ausgewählten Beacons genauso auf, wie Eugene die installierten Werkzeuge auflistet. Das LLM plant gegen Fähigkeiten statt gegen Annahmen. Ein Tool, dessen Capability fehlt, wird dem Modell **nicht angeboten** — nicht erst zur Laufzeit abgelehnt.

---

## 8. Die Agenten-Schleife

Übernommen von Eugene, einschließlich der Zahlen, die sich dort als tragfähig erwiesen haben.

### 8.1 Topologie

```
run_campaign(scope, beacons, config)
  ├─ Capabilities der Ziel-Beacons einsammeln
  ├─ Run-Datensatz anlegen → run_id
  ├─ asyncio.Semaphore(max_concurrent_executors = 4)
  ├─ Orchestrator  (Tools: dispatch ×2, memory ×3, score ×2, scripts ×3, set_phase → 11; 20 Turns)
  │    └─ dispatch_task / dispatch_parallel_tasks
  │         └─ Executor (bis 16 Tools; 16 Turns)
  │              └─ router → Klassifikation → Gate → Beacon-Lane | Server-Tool
  └─ finally: Beacon-Intervall zurücksetzen, Run abschließen
```

Es gibt **keinen handgeschriebenen Planer.** Die Zerlegung macht das LLM; der Preamble beschreibt die Phasen, der Orchestrator wählt zwischen einzelner und paralleler Zuweisung. Durchgesetzt wird das strukturell: der Orchestrator hat **kein** `run_command`.

### 8.2 Turn-Budgets

| Rolle | Turns | Tools | Temperatur | max_tokens |
|---|---|---|---|---|
| Orchestrator | 20 | 11 | 0.3 | 4096 |
| Executor | 16 | bis 16 | 0.3 | 4096 |

Die Werte werden pro Fähigkeitsstufe des Modells reduziert (Abschnitt 13).

### 8.3 Nebenläufigkeit

`asyncio.Semaphore(4)`, erworben **in der Dispatch-Schleife vor dem Erzeugen der Task**, nicht innerhalb. Das ist der Grund, warum bei Eugene `Semaphore(1)` auch paralleles Dispatch serialisiert — dieselbe Eigenschaft wird hier gebraucht, um Wifi-Operationen auf einem einzelnen Adapter zu serialisieren.

Python 3.9 hat keine `TaskGroup`; verwendet wird `asyncio.gather(..., return_exceptions=True)`.

### 8.4 Fehler sind Werte, keine Ausnahmen

Durchgängiges Prinzip, von Eugene übernommen: Dispatch gibt **nie** eine Exception an das LLM zurück. Fehlgeschlagene Executors, Timeouts und Abstürze kommen als `[ERROR] …`-Text zurück, damit der Orchestrator darüber nachdenken kann, statt den Turn abzubrechen.

Gleiches für Tools: `run_command` wandelt einen Exit-Code ≠ 0 in `{"success": false, "exit_code": n, "stderr": …}` statt zu werfen. Eine Gate-Ablehnung kommt als `{"allowed": false, "reason": …}` zurück — das LLM soll die Begründung lesen und umplanen können.

### 8.5 Kontextzusammenstellung

Kein RAG, keine automatische Einspeisung. Kontext kommt aus vier Quellen:

1. **Statischer Preamble** mit eingespleißten Capabilities und Scope.
2. **Gesprächsverlauf innerhalb einer Rolle.** Der Orchestrator sieht seine eigenen Tool-Calls und alle Dispatch-Ergebnisse. Executors sind **kurzlebig und isoliert** — kein gemeinsamer Zustand zwischen parallelen Executors.
3. **Explizite werkzeuggestützte Erinnerung.** `recall_findings`, `get_run_summary`, `get_score_context`, `search_memory`. Der Preamble weist an, diese vor jeder Phasenplanung aufzurufen.
4. **Fortsetzung.** Ein pausierter oder abgebrochener Lauf kann fortgesetzt werden; die Findings der vorherigen Phasen sind über `recall_findings` zugänglich.

> Anmerkung: Eugene lädt einen Telegram-Sitzungsverlauf, übergibt ihn aber nie an das Modell — gebaut und wirkungslos. Dieser Fehler wird nicht nachgebaut.

### 8.6 Phasen

**Mechanisch durchgesetzt wird genau eine Grenze: Phase 5.** Die Phasen 1–4 sind Reihenfolge-Empfehlung im Preamble; sie zu erzwingen hätte keinen Schutzwert und würde das LLM unnötig behindern.

- Ist **Phase 5 abgeschaltet**, blockiert `safety.py` alle Aktionen der Exploitation-Klasse hart, unabhängig vom Preamble. Die Klassifikation nutzt dieselbe Aktionstabelle wie das EV-Gate (Abschnitt 10.5).
- Der Orchestrator meldet Phasenwechsel über das Tool **`set_phase`**. Nur dadurch ist die Anzeige „Phase 3/5" im Drawer ehrlich; ohne dieses Tool wäre sie Dekoration.
- `runs` und `tasks` tragen ein `phase`-Feld.

### 8.7 Pause und Fortsetzung

`runs.status` kennt: `running`, `paused`, `completed`, `failed`, `aborted`.

**Pause** (`POST /api/ai/pause`) bedeutet:
- keine neuen Tasks werden dispatcht und keine neuen Executors gestartet
- **laufende Executors werden fertiggestellt**, ihre Ergebnisse normal gespeichert
- das abgesenkte Beacon-Intervall **bleibt**, weil eine Fortsetzung wahrscheinlich ist
- der Orchestrator-Turn-Zähler wird festgehalten

**Fortsetzung** (`POST /api/ai/resume`) setzt denselben `run_id` fort mit **frischem Turn-Budget**. Die bisherigen Findings erreicht das Modell über `recall_findings`; der volle Gesprächsverlauf wird nicht wiederhergestellt.

**Der Intervall-Rücksetzer gehört in den `finally`-Pfad** und greift nur bei den Endzuständen `completed`, `failed`, `aborted` — nicht bei `paused`. Er muss auch bei Absturz des Agenten-Dienstes greifen: beim Start prüft der Dienst auf Läufe in `running`/`paused` ohne lebende Task und setzt deren Beacons zurück.

### 8.8 Ausführungspfade

Der `router` klassifiziert jede Aktion, ruft bei Stufe 2 das Gate, und wählt dann den Pfad:

| Pfad | Mechanik | Latenz |
|---|---|---|
| **Beacon-Lane** | `POST /api/agents/<id>/task` mit `lane="agent"`, dann `GET /api/tasks/<tid>` pollen (2 s) bis `status != "pending"` | Check-in-Intervall, in Kampagnen 15 s |
| **Server-Tool** | `POST /api/server/exec` mit argv und `run_id`, dann `GET /api/server/exec/result/<run_id>` pollen | Sekunden bis Minuten |

Ausgabe-Kürzung: Kopf 2000 + Markierung + Schwanz 2000 **Zeichen, nicht Bytes** (Eugene schneidet Bytes und riskiert UTF-8-Brüche). Das `truncated`-Flag wird auf beiden Pfaden korrekt gesetzt.

Timeouts töten das Kind. Eugene lässt es im Timeout-Fall nur fallen; `asyncio.subprocess`-Kinder müssen explizit terminiert werden, sonst bleiben lange Scans als Waisen zurück.

---

## 9. Serverseitige Werkzeugausführung

Drei Änderungen an `/api/server/exec`, weil der heutige Zustand drei Zusagen dieses Dokuments bricht.

### 9.1 argv statt Shell

Der Endpoint akzeptiert künftig **beides**:

- `{"cmd": "<string>"}` — unverändert, `shell=True`, für das bestehende GUI. Operator-Herkunft.
- `{"argv": ["nmap","-sV","10.0.1.5"]}` — neu, `asyncio.create_subprocess_exec`, kein Shell. **Der Agent darf ausschließlich diese Form nutzen.**

Damit gilt die Zusage aus Abschnitt 10.2 („kein Shell") für alle Agent-Aktionen, ohne das GUI zu brechen. Der Agenten-Client verweigert die String-Form.

### 9.2 Timeout und Teilausgabe

Das feste 300-s-Timeout verträgt sich nicht mit erzwungenem `-T2 --max-rate 50`: ein Service-Scan über zwanzig Hosts überschreitet es und liefert heute `[timeout after 300s]` ohne jede Ausgabe.

- `timeout` wird pro Aufruf übergeben, Vorbelegung bleibt 300 s.
- Werkzeugspezifische Vorbelegungen analog zu Eugene (`nmap` 900 s, `tcpdump` 30 s, `aircrack-ng` 1800 s, Rest 60 s), aufgelöst über den **Basenamen** des Binaries — Eugene trifft hier `sudo nmap` und `/usr/bin/nmap` nicht.
- Bei Timeout wird die bis dahin gelesene Ausgabe **behalten** und mit `[timeout after Ns, partial output]` markiert.

### 9.3 Zuordnung

`tool_runs[run_id]` trägt `origin`. Der alte parameterlose Result-Endpoint liefert den jüngsten Lauf mit `origin == "operator"`, damit vier parallele Agent-Läufe das Operator-Panel nicht überschreiben.

---

## 10. Sicherheit und die Leine

Das Leitprinzip unterscheidet sich bewusst von Eugene. Eugenes Safety-Layer schützt **die Pi vor Selbstzerstörung** (`rm`, `dd`, `mkfs`, `shutdown`), alles Offensive ist unbeschränkt. Hier wird **die Operation** geschützt. Die beiden Risiken sind Verbindungsverlust und Enttarnung.

Es bleibt eine **Blocklist-Architektur** ohne Allowlist: was nicht ausdrücklich eingeschränkt ist, darf der Agent.

### 10.1 Drei Stufen

**Stufe 1 — Hart blockiert, in jedem Modus, nicht konfigurierbar.**

Unumkehrbare Aktionen. Entscheidet der Agent hier falsch, ist die Box weg und es gibt keinen Rückweg, weil im Full-Auto niemand zuschaut. Dieses Risiko kann die EV-Rechnung nicht bepreisen, weil sie den Verlust ihres eigenen Sensors nicht modelliert.

- Beacon-Steuerung: `kill`, `unpersist`, `reconfig`
- `sleep` mit einem Wert über dem Schwellwert
- Netzwerk-Konfiguration auf dem Beacon-Host: `ip`, `ifconfig`, `nmcli`, Firewall-Regeln, NetworkManager-Neustart
- Reboot/Shutdown des Beacon-Hosts
- Alles auf der Drop-Box, das Bridge, NAC-Bypass, Cover-Identität oder SSH-Tunnel berührt — `bridge_tap.py`, `nac_bypass.py`, `br0`, `eth0`, `eth1`, die Cover-Ports aus `raccoon.yaml`
- Monitor-Mode auf dem Interface, das den Uplink trägt
- `airmon-ng check kill` (tötet NetworkManager)
- **Jedes Ziel, das nicht positiv in der Scope-Allowlist auflösbar ist** (Abschnitt 10.4)
- Exploitation-Klasse, wenn Phase 5 abgeschaltet ist
- Eugenes Pi-Schutzliste bleibt zusätzlich in Kraft, angewendet auf die C2-Box

**Stufe 2 — Anklopfen. OpSec- und Resilienz-relevant.**

Im überwachten Modus geht die Frage an den Operator, im Full Automated an den EV-Schiedsrichter. **Das Gate verschwindet nie, nur der Entscheider wechselt.**

*OpSec:* Responder / LLMNR-NBT-NS-mDNS-Poisoning · NTLM-Relay und Coercion (PetitPotam, DFSCoerce, PrinterBug) · Deauth · LSASS-Zugriff und Credential-Dumping · Shadow-Copy-Löschung, Log-Clearing · Domain-Controller als Ziel · alles, was die Cover-Identität bricht · Exfiltration über einem Volumenschwellwert

*Resilienz:* `persist` (Installation, nicht Entfernung) · Monitor-Mode auf einem Interface, das nicht der Uplink ist · Dienste auf dem Beacon-Host beenden

**Stufe 3 — Frei, aber protokolliert und umgeschrieben.**

Alles andere. Laute Scans werden **nicht** zum Anklopfen, sondern still korrigiert, wie bei Eugene:

- `nmap` → `-T[0-5]` und `--max-rate N` entfernen, `-T2 --max-rate 50` erzwingen
- `masscan` → `--rate 50` erzwingen
- `netdiscover` → `-c 1` ergänzen (nicht doppeln, wenn vorhanden)
- Kein Service-Detection-Scan über ein ganzes /24 in einem Befehl

### 10.2 Injection-Verhinderung

Zwei Mechanismen, wie bei Eugene:

1. **Metazeichen-Ablehnung** — `[;&|`$()>\n]` irgendwo im Befehl ist eine harte Ablehnung. Das blockiert Verkettung, Pipes, Kommandosubstitution und Umleitung.
2. **Kein Shell.** Server-Tools laufen über die argv-Form (Abschnitt 9.1), nie `shell=True`.

Zu akzeptierende Einschränkung: Argumente mit Leerzeichen lassen sich über einen naiven Whitespace-Split nicht ausdrücken, Globs und Umleitungen funktionieren nicht.

Für den **Beacon-Pfad** gilt die Metazeichen-Prüfung ebenso, auch wenn `_exec_shell` dort mit `shell=True` arbeitet — das ist bestehendes Beacon-Verhalten und wird nicht geändert, aber der Agent darf es nicht mit zusammengesetzten Kommandos füttern.

> **Wichtige Abweichung von Eugene:** dort umgeht `run_script` den Safety-Layer vollständig — beliebiges LLM-geschriebenes Bash läuft ungeprüft. Hier wird **jede Zeile** eines gespeicherten Skripts beim Speichern **und** beim Ausführen durch dieselbe Prüfung geschickt wie ein direkter Befehl. Andernfalls ist die gesamte Leine mit drei Zeilen Python umgehbar — siehe Anti-Ziele.

### 10.3 Wifi-Stufung

| Erkannter Zustand | Freigegeben |
|---|---|
| Kein WLAN-Interface | nichts |
| Onboard `brcmfmac`, ist Uplink | nichts (Stufe-1-Block) |
| Onboard `brcmfmac`, nicht Uplink | passives Scannen (`wifi:scan`) |
| Monitor-fähiger Adapter | volle Kette (`wifi:monitor`) |

Deauth-Governance von Eugene übernommen: Paketzahl ≤ 10, `--deauth 0` (unendlich) abgelehnt, 30-Sekunden-Abkühlung pro BSSID.

Wifi-Operationen laufen über `Semaphore(1)` — ein physischer Adapter verträgt keine Parallelität.

### 10.4 Scope-Durchsetzung: fail-closed

Das stärkste Versprechen dieses Dokuments muss auch das strengste sein. **Ein Befehl, dessen Ziele nicht vollständig und positiv in die Allowlist aufgelöst werden können, wird abgelehnt.** Nicht „best effort", weil ein fail-open-Scope die Stufe-1-Garantie zur Behauptung macht.

Erkannt werden:

- einzelne IPv4/IPv6-Adressen
- CIDR-Notation
- Bereiche der Form `10.0.1.1-254` und `10.0.1.1-10.0.1.254`
- Hostnamen, **nur** wenn sie über einen Fund in `findings` einer Adresse im Scope zugeordnet sind
- `-` / `--target-file` / Argumente, die auf eine Datei zeigen: **Ablehnung**, der Agent muss Ziele explizit nennen

Nicht auflösbare Ziele führen zu einer Gate-Antwort mit Begründung, die das LLM lesen und korrigieren kann („nenne Ziele einzeln"). Die Preambles steuern entsprechend auf explizite Einzelziele zu.

Die Allowlist gilt zusätzlich zur Denylist; die Denylist gewinnt immer.

### 10.5 Die Risikotabelle — woher die EV-Zahlen kommen

Das Gate feuert im `router`, **nicht** als LLM-Tool. `request_approval` existiert bewusst nicht, sonst könnte das Modell es durch Nichtaufruf umgehen. Damit muss der `router` die EV-Zahlen selbst haben — sie können nicht vom LLM kommen, sonst ist das Gate durch Tiefmelden des Risikos manipulierbar.

**`safety.py` enthält eine statische Tabelle** `aktion → (klasse, punkte, p_erfolg_prior, p_detect_prior, phase)`. Beispielzeilen:

| Aktion | Klasse | Punkte | P(erfolg) | P(detect) |
|---|---|---|---|---|
| LSASS-Dump | credential_access | 50 | 0.50 | 0.70 |
| Responder (poison) | credential_access | 50 | 0.60 | 0.55 |
| NTLM-Relay | lateral | 75 | 0.40 | 0.50 |
| `persist` installieren | persistence | 0 | 0.90 | 0.25 |
| Deauth | wifi | 30 | 0.70 | 0.40 |
| Exploit mit bekanntem PoC | exploitation | 25 | 0.60 | 0.30 |

Das LLM darf über Tool-Argumente **Korrekturen vorschlagen** (etwa eine höhere Erfolgswahrscheinlichkeit, wenn `check_exploit` einen Remote-Exploit gefunden hat). Diese Vorschläge werden **geklammert** auf ±0.2 um den Prior und protokolliert. Eugenes CVSS-Tabelle bleibt im Preamble als Richtlinie für die **Planung** des Modells — sie ist nicht die Rechengrundlage des Gates.

### 10.6 Was als Detection gilt

Zwei Quellen:

1. **Ausgabemuster**, im `router` nach jeder Aktion geprüft: `connection reset by peer`, `No route to host` nach vorher erfolgreichem Kontakt, `blocked`, `denied by policy`, bekannte IDS-/WAF-Kennungen, plötzliche Totalausfälle eines vorher antwortenden Hosts.
2. **Explizite Meldung** des Modells über `log_score detection`.

Nachführung:

```
P(detect)_effektiv = min(0.95, p_detect_prior + 0.15 × detections_bisher)
```

Das Detection-Budget (Vorbelegung 3) ist eine **harte Abbruchbedingung**, keine Statistik: beim Erreichen wird der Lauf auf `aborted` gesetzt, der Beacon-Intervall zurückgesetzt und der Operator benachrichtigt.

Mit dem Vorbelegungsprofil bedeutet das: nach einer Detection steigt P(detect) um 0.15, was die meisten Stufe-2-Aktionen mit Punkten unter 100 automatisch unter die EV-Schwelle drückt. Die Leine zieht sich also messbar an, ohne den Agenten nach dem ersten TCP-Reset vollständig zu sperren.

### 10.7 Approval-Mechanik

```
Agent will eine Aktion
  → safety.classify(aktion) → (stufe, klasse, punkte, p_erfolg, p_detect, begründung)
  → Stufe 1 → sofortige Ablehnung, nicht erlaubbar, auch nicht im Full-Auto
  → Stufe 2 → gate.request(run_id, aktion, klassifikation, ev)
        → Zeile in approvals (status="pending"), Ereignis in den Stream
        → auf asyncio.Event warten, mit Timeout
     · überwachter Modus:  Operator antwortet über /api/ai/approve → Event gesetzt
     · Full Automated:     EV-Schiedsrichter entscheidet sofort, Entscheidung protokolliert
     · Timeout:            Verhalten aus der Konfiguration (Vorbelegung: Kampagne pausieren)
  → Stufe 3 → durchlassen, Scan-Limits anwenden
  → Rückgabe ans LLM: {"allowed": bool, "reason": str}
```

Jede Anfrage und jede Entscheidung landet in `approvals`, mit `decided_by` = `"operator"` | `"ev"` | `"timeout"`.

### 10.8 EV-Gating

```
EV = (punkte × P(erfolg)) − (100 × P(entdeckung)_effektiv)
```

Durchführung nur bei `EV > schwelle`. Punktetabelle (identisch zur Scoring-Tabelle):

| Aktion | Punkte | | Aktion | Punkte |
|---|---|---|---|---|
| `host_discovered` | +10 | | `successful_login` | +75 |
| `port_found` | +5 | | `privilege_escalation` | +150 |
| `service_identified` | +15 | | `rce_achieved` | +200 |
| `os_fingerprinted` | +20 | | `data_exfiltrated` | +100 |
| `vuln_detected` | +25 | | **`detection`** | **−100** |
| `credential_captured` | +50 | | | |

Wifi: `ap_discovered` +5, `handshake_captured` +30, `pmkid_captured` +30, `wps_pin_found` +50, `psk_cracked` +75.

> Eugene bewirbt die Wifi-Aktionen in keinem Preamble — das LLM kann sie nur über Fehlermeldungen entdecken. Hier stehen alle Aktionen im Preamble.

Das Scoring läuft **immer**, weil es das Gate treibt. Der konfigurierbare Modus betrifft nur die Darstellung als CTF-Wertung im GUI.

---

## 11. Datenmodell

SQLite in `data_dir/agent.db`, WAL, `foreign_keys=ON`. FTS5 wird geprüft; **fehlt es, wird auf `LIKE`-Suche zurückgefallen statt den Start zu verweigern** (Eugene bricht hier ab — unnötig hart für eine Nebenfunktion).

```
runs              id, trigger_type, trigger_data, mode, status, phase, config_json,
                  started_at, completed_at
tasks             id, run_id→runs, name, description, lane, phase, status, result,
                  beacon_agent_id, c2_task_id, created_at, completed_at
findings          id, run_id→runs, host, finding_type, data, source, timestamp
score_events      id, run_id→runs, action, points, risk_level, detected, timestamp
approvals         id, run_id→runs, action, classification_json, ev_json,
                  decision, decided_by, requested_at, decided_at
memories          id, scope_key, topic_key, content, sector, salience,
                  created_at, accessed_at        + FTS5(content)
scripts           id, name UNIQUE, description, language, tags, code,
                  use_count, created_at, updated_at, last_run_at   + FTS5
scheduled_tasks   id, prompt, config_json, schedule, next_run, last_run,
                  last_result, status, running_run_id, created_at
cve_cache         id, cache_key, cve_id, description, cvss_score, cvss_vector,
                  severity, references_json, published, source, fetched_at
wire_intel        id, run_id→runs, src, dst, proto, port, observation,
                  credential_json, first_seen, last_seen
wifi_aps          id, run_id→runs, bssid, essid, channel, encryption, signal_dbm,
                  client_count, wps_enabled, first_seen, last_seen
wifi_clients      id, run_id→runs, mac, associated_bssid, signal_dbm, probes_json,
                  first_seen, last_seen
wifi_credentials  id, run_id→runs, bssid, essid, psk, crack_method, cap_file, cracked_at
llm_interactions  id, run_id→runs, request_id, provider, model, caller_context,
                  prompt_text, response_text, input_tokens, output_tokens,
                  total_tokens, latency_ms, status, error_message, created_at
```

**Zeitstempel durchgängig RFC3339-TEXT in UTC.** Eugene mischt TEXT und Unix-Integer über Tabellen hinweg — das wird nicht nachgebaut.

`llm_interactions` ist das revisionssichere Protokoll aus Ziel 3. Prompt- und Antworttext werden nur bei Log-Stufe `full` gespeichert; Token-Zahlen, Latenz und Status immer.

### Was angeschlossen wird, anders als bei Eugene

Eugene hat erhebliche Mengen gebauten, getesteten und **nie aufgerufenen** Codes. Nach der Entscheidung aus dem Gespräch werden drei dieser Teile tatsächlich verdrahtet:

| Teil | Bei Eugene | Hier |
|---|---|---|
| Memory mit Salience-Verfall | gebaut, `spawn_decay_task` nie aufgerufen, keine Tools | **angeschlossen** — `save_memory`/`search_memory` als Tools, Verfallslauf beim Dienststart |
| CVE-Lookup (OSV + NVD) | gebaut, `lookup_cves` von keinem Tool erreichbar | **angeschlossen** — als Tool, searchsploit zur Exploit-Prüfung daneben |
| Cron-Scheduler | nur im Bot-Modus, CLI-Einträge liefern an `ChatId(0)` | **angeschlossen** — Poll-Schleife im Agent-Dienst, Ergebnis über `notifications.py` |
| `turns`, `game_state` | toter Code | **nicht übernommen** |
| Telegram-Bot, TUI | vorhanden | **nicht übernommen** (GUI ist die Oberfläche) |

Verfallsformel unverändert: `salience *= 0.98` pro Tageslauf für Einträge älter als 24 h, Löschung unter 0.1. Verstärkung beim Lesen: `+0.1`, gedeckelt bei 5.0.

Der Scheduler bekommt eine **Überlappungssperre** über `running_run_id`, die Eugene fehlt: eine fällige Aufgabe startet nicht, solange ihr vorheriger Lauf noch läuft.

---

## 12. Prompts

Vier Preambles, Struktur von Eugene übernommen, Inhalt angepasst:

1. **Orchestrator** — Phasen 1–5, Dispatch-Regeln, vollständige Scoring-Tabelle (inklusive Wifi), EV-Gating mit CVSS-Richtlinie, Scan-Ratenlimits, Capability-Liste der Ziel-Beacons, aktiver Scope mit der Anweisung, Ziele **einzeln** zu benennen, und die Stufe-1/2-Listen mit dem Hinweis, dass Stufe-2-Aktionen durch ein Gate laufen und abgelehnt werden können.
2. **Executor** — eine fokussierte Aufgabe, `run_command` und Protokollierung, striktes Scope-Verbot („nicht abschweifen, nicht ausweiten"), festes Ausgabeformat `TASK/STATUS/FINDINGS/ERRORS`.
3. **Wifi-Orchestrator** — nur bei `wifi:monitor`. Enthält Eugenes wichtigste Regel: **niemals parallele Wifi-Aufgaben**, ein Adapter ist eine einzelne physische Ressource.
4. **Wire-Recon** — neu, kein Eugene-Gegenstück. Für Beacons mit `sniffer`: leite aus dem Mitschnitt ab, welche Hosts, Protokolle und Klartext-Credentials über die Bridge gelaufen sind, **bevor** ein eigenes Paket gesendet wird.

Der Phasenplan beginnt deshalb anders als bei Eugene:

| Phase | Eugene | Hier |
|---|---|---|
| 1 | Orientation (Interfaces, ARP) | **Wire Intel** — passiver Mitschnitt auswerten, falls `sniffer` |
| 2 | Network Discovery | Orientation + Discovery |
| 3 | Port & Service Enum | Port & Service Enum |
| 4 | OS & Vuln Fingerprint | OS & Vuln Fingerprint + CVE-Lookup |
| 5 | Exploitation | Exploitation, EV-gated, standardmäßig aus |

Die leiseste Informationsquelle kommt zuerst. Das ist der direkte Vorteil der Bridge-Position und der Grund, warum der Sniffer das Wifi-Gegenstück aus Eugene ersetzt.

---

## 13. LLM-Anbieter und Fähigkeitsstufen

| Anbieter | Protokoll | SDK |
|---|---|---|
| Anthropic | Anthropic Messages | `anthropic` (async) |
| OpenRouter | OpenAI-kompatibel | `openai` mit `base_url` |
| OpenCode Zen | OpenAI-kompatibel | `openai` mit `base_url` |
| Lokal (Ollama, LM Studio, llama.cpp) | OpenAI-kompatibel | `openai` mit `base_url` |

Auflösungskaskade: **CLI > YAML > Umgebungsvariable > Vorbelegung**. API-Keys werden mit `0600` gespeichert und nie in der YAML im Repo.

### Fähigkeitsstufen

Eugenes Schleife setzt verlässliches Tool-Calling über viele Turns voraus. Ein 8B-Modell mit 8k Kontext ist nach drei `nmap`-Ergebnissen voll und beginnt, Tool-Namen zu erfinden. Deshalb drei Stufen, überschreibbar:

| Stufe | Orch.-Turns | Exec.-Turns | Tools | Kürzung | Phasen |
|---|---|---|---|---|---|
| **voll** | 20 | 16 | alle | 4000 | 1–5 (+ Wifi) |
| **reduziert** | 12 | 8 | Kernmenge | 2000 | 1–4 |
| **minimal** | 8 | 6 | `run_command`, `log_discovery` | 1000 | 1–3 |

Für Modelle ohne natives Tool-Calling: **Text-Protokoll-Fallback** — Tool-Aufrufe werden als Block im Antworttext angefordert und geparst. Langsamer und fehleranfälliger, aber brauchbar für Recon.

Die Stufe erscheint im Konfigurationsformular, damit der Operator sieht, warum Phase 5 gesperrt ist.

---

## 14. LLM-Werkzeuge

### Orchestrator (11)

`dispatch_task` · `dispatch_parallel_tasks` · `set_phase` · `remember_finding` · `recall_findings` · `get_run_summary` · `log_score` · `get_score_context` · `save_script` · `search_scripts` · `run_script`

### Executor (bis 16, capability-abhängig)

`run_command` · `log_discovery` · `save_script` · `search_scripts` · `run_script` · `check_exploit` · `lookup_cve` · `save_memory` · `search_memory` — bei `sniffer`: `get_wire_intel` — bei `wifi:scan`: `wifi_scan` — bei `wifi:monitor`: `run_airodump` · `capture_pmkid` · `capture_handshake` · `wps_attack` · `crack_wpa` · `get_wifi_intel`

Bewusste Asymmetrie, von Eugene übernommen: Executors haben **keine** Dispatch-Tools (verhindert Rekursion) und **kein** Scoring (nur der Orchestrator bewertet).

`request_approval` ist **kein** Tool — Begründung in Abschnitt 10.5.

Tools ohne passende Capability werden dem Modell nicht angeboten.

---

## 15. Teilprojekt: Wire Intel

**Existiert heute nicht.** Der Sniffer (`software/sniffer/bridge_tap.py`, `pcap_writer.py`) schreibt rotierende, optional GPG-verschlüsselte pcaps in das Capture-Dir aus `raccoon.yaml` — mit BPF-Portfiltern, aber ohne Credential-Extraktion, ohne Host- oder Protokollübersicht und ohne Abfrageschnittstelle. `BridgeTap` und `Beacon` sind in `main.py` zwei Objekte ohne Verbindung.

### Entscheidung: Auswertung auf der Box

Drei Wege waren denkbar: pcaps zum C2 ziehen und dort auswerten; den Sniffer zum Mitschreiben von Zusammenfassungen erweitern; auf der Box auswerten.

**Gewählt: auf der Box auswerten, über neue `wire`-Kommandos im Beacon.** Begründung:

- scapy ist auf der Box bereits installiert und `bridge_tap.py` nutzt es schon — keine neue Abhängigkeit.
- Es werden **Zusammenfassungen statt Rohmitschnitte** exfiltriert. Ein /24 über eine Stunde sind hunderte MB pcap; die Zusammenfassung sind Kilobytes. Das ist sowohl eine OpSec- als auch eine Bandbreitenfrage.
- Das C2-Image braucht kein `tshark` (es hat heute keins).
- `BridgeTap` und `Beacon` bleiben entkoppelt — der Beacon liest nur Dateien vom Dateisystem.

### Neue Beacon-Kommandos

| Kommando | Argumente | Ergebnis |
|---|---|---|
| `wire summary` | `[seit]` | Hosts, MACs, Protokolle, Portpaare, Paketzahlen aus den vorhandenen pcaps |
| `wire creds` | `[seit]` | Klartext-Credentials aus den Protokollen, die `capture_profiles` ohnehin filtert (FTP, Telnet, SMTP, POP3, IMAP, HTTP-Basic) |
| `wire hosts` | — | Host-Inventar mit erstem/letztem Auftreten und abgeleiteter Rolle (Server/Client) |
| `wire dns` | `[seit]` | beobachtete DNS-Anfragen und -Antworten |

Alle lesen ausschließlich **bereits geschriebene** pcaps — sie starten keinen neuen Mitschnitt und verändern den Sniffer nicht. GPG-verschlüsselte Mitschnitte werden übersprungen mit entsprechender Meldung.

Ergebnisse landen in `wire_intel` und über `get_wire_intel` im Kontext des Modells.

**Nicht in diesem Projekt:** aktives Eingreifen in den Datenpfad (Injection, Rewriting). Der Tap bleibt passiv.

---

## 16. Teilprojekt: Wifi-Kette

**Existiert heute nicht.** Kein Wifi-Code im Repo, keine Adaptererkennung, keine Beacon-Kommandos, kein `aircrack-ng` oder `hcxtools` in irgendeinem Image. Die einzigen WLAN-Erwähnungen betreffen die Provisionierung beim ersten Boot.

### Umfang

1. **Adaptererkennung** auf der Box: sysfs-Treiber-Symlink gegen `88XXau`, `rtl8812au`, `8812au`; Uplink-Erkennung über die Default-Route. Ergibt `wifi:scan` oder `wifi:monitor` (Abschnitt 7.3).
2. **Monitor-Mode-Umschaltung** mit Wiederherstellung — ein Kontextmanager, der den Managed-Mode auch bei Exception zurücksetzt. Niemals auf dem Uplink-Interface (Stufe-1-Block).
3. **Neue Beacon-Kommandos:** `wifi scan`, `wifi airodump`, `wifi pmkid`, `wifi handshake`, `wifi wps`, `wifi crack`.
4. **Paketierung:** `aircrack-ng`, `hcxtools`, `reaver`, `wash` ins Box-Image (`software/setup/build_image.sh`), nicht ins C2-Image.
5. **Capture-Rückholung:** `.cap`/`.22000`-Dateien über den bestehenden `download`-Pfad in die Loot-Vault.
6. **Wordlist-Stufen** wie bei Eugene: Tier 1 = Top 1.000, Tier 2 = Top 100.000, Tier 3 = vollständige `rockyou.txt` nur auf ausdrückliche Anweisung. Vorbelegung Tier 2.

Übernommen werden Eugenes zwei nicht offensichtliche Erkenntnisse, beide als Kommentar im Code zu vermerken: `aircrack-ng` liefert **Exit-Code 0 auch ohne gefundenen Schlüssel** — es muss auf `KEY FOUND! [ … ]` im stdout geparst werden; und die Handshake-Verifikation muss auf den Literaltext `1 handshake` prüfen, nicht auf den Exit-Code.

### Testbarkeit

**Kein monitor-fähiger Adapter verfügbar.** Daraus folgt:

- `wifi scan` ist auf dem onboard-`brcmfmac` real testbar.
- `wifi airodump`, `pmkid`, `handshake`, `wps`, `crack` sind **ausschließlich gegen Mocks geprüft** — Ausgabeparser gegen aufgezeichnete Beispielausgaben, Ablauflogik gegen gefälschte Subprozesse.
- Diese Kommandos tragen im Code einen Hinweis, dass sie nicht gegen echte Hardware verifiziert sind.
- Die Safety-Seite (Deauth-Grenzen, Abkühlung, Uplink-Schutz) ist vollständig testbar und wird vollständig getestet.

Der Parser für airodump-CSV ist eine reine Funktion und damit gut prüfbar: zwei Abschnitte, Wechsel bei einer Zeile, die mit `BSSID` bzw. `Station MAC` beginnt, Trennung an `, `, fehlerhafte Zeilen zählen statt zu werfen.

---

## 17. Operator-Oberfläche

### 17.1 Überwachter Modus — drei Regionen

Bestätigt am Mockup. Jede Region hat eine eigene Aufgabe:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ RACCOON C2                                            3 agents · 1 campaign │
├──────────┬──────────────────────────────────────────────┬────────────────────┤
│ Agents   │ [Files][procs][netstat][Beacon][Impacket]    │ sweep-dmz          │
│ ●fox  AI │                      [● Automated Attack]    │ Phase      3 / 5   │
│ ●owl     ├──────────────────────────────────────────────┤ ███████░░░ 62%     │
│ ○bat     │ ◆ AGENT · PHASE 3/5     [Agent|Alles] ⏸      │ Score        185   │
│          │ › dispatch_parallel_tasks ×2                 │ Detections   1/3   │
│ Campaign │ › remember_finding 10.0.1.5 [service] SMB    │ Tasks      14/22   │
│ ◆sweep   │ › EV: 25×0.60 − 100×0.12 = +3.0 → proceed    │ Tokens   41k/500k  │
│  11m     │ › ⚠ Detection — reset von 10.0.1.20  −100    │ Laufzeit   11m/2h  │
│          │ ╌╌╌╌╌╌╌╌╌╌╌╌╌╌ ziehbar ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌  │ SCOPE              │
│          │ OP $ smbloot 10.0.1.5 svc_backup … shares    │ ✔ 10.0.1.0/24      │
│          │ ADMIN$ C$ IPC$ SYSVOL Backups                │ ✔ 10.0.2.0/24      │
│          │ OP $ _                                       │ ✘ 10.0.9.0/24      │
│          │                                              │ ⚠ ANKLOPFEN 1/1    │
│          │                                              │ LSASS auf …1.20    │
│          │                                              │ OpSec: hoch        │
│          │                                              │ EV: −45            │
│          │                                              │ [Erlauben][Nein]   │
└──────────┴──────────────────────────────────────────────┴────────────────────┘
```

**① Agent-Stream (oben, ziehbar, zuklappbar).** Volle Textbreite, damit die EV-Begründung in eine Zeile passt statt im Streifen abzubrechen. Toggle **Agent / Alles** schaltet auf eine chronologisch zusammengeführte Ansicht beider Akteure — dafür sind die `AI`/`OP`-Badges da. Ein Klick auf eine Zeile öffnet Details als Panel: vollständige Tool-Argumente, Rohausgabe, zugehörige LLM-Interaktion. Das ⏸-Symbol pausiert die Kampagne (Abschnitt 8.7).

**② Operator-Terminal (unten).** Nur eigene Kommandos und deren Ausgabe, Prompt immer erreichbar. Spiegelt die Task-Lanes: was der Operator tippt, geht beim nächsten Check-in raus, unabhängig von der Länge des Agentenplans.

**③ Drawer (rechts).** Nur Dinge, die nicht wegscrollen dürfen: Fortschritt, Score, Detection- und Budget-Zähler, aktiver Scope, und das Anklopfen als angepinnte Karte mit beiden Gründen und der EV-Zahl. Im Stream steht dazu nur eine Protokollzeile; entschieden wird im Drawer.

**Ohne laufende Kampagne verschwinden ① und ③ vollständig.** Das GUI ist dann exakt das heutige, plus einen Knopf.

### 17.2 Full Automated — Konfigurationsformular

Bestätigt am Mockup. Alle fünf markierten Entscheidungen wurden abgenommen.

| Abschnitt | Inhalt | Vorbelegung |
|---|---|---|
| **Ziel-Beacons** | Mehrfachauswahl aus der Flotte | keine Automatik für neu eincheckende Beacons |
| **Scope** | CIDR-Allowlist und -Denylist | leer, muss gefüllt werden |
| **Phasen** | 1–5 einzeln, 6–8 Wifi fähigkeitsabhängig | 1–4 an, **5 aus**, Wifi nach Capability |
| **Risikoprofil** | Preset Passiv/Normal/Aggressiv, setzt EV-Schwelle, P(entdeckung)-Startwert, Detection-Budget — einzeln überschreibbar | Normal: Schwelle 0, P 0.15, Budget 3 |
| **Anklopfen ohne Operator** | *Autonom entscheiden* / *Überspringen* / *Pausieren* | Autonom entscheiden |
| **Budget & Abbruch** | max. Laufzeit, max. Tokens, Beacon-Intervall während der Kampagne | 2 h, 500k, 15 s |
| **Modell** | Anbieter, Modell, angezeigte Fähigkeitsstufe | aus der Konfiguration |
| **Zeitplan** | Jetzt starten oder Cron | jetzt |

Die nicht konfigurierbare Stufe-1-Liste wird im Formular **angezeigt** mit der Begründung, dass sie unumkehrbar und ohne Operator nicht korrigierbar ist.

Konfigurationen sind als Preset speicherbar.

**Zum Beacon-Intervall:** 15 s machen den Agenten brauchbar, erhöhen aber die Check-in-Rate von 12 auf 240 pro Stunde. Der Rücksetzer gehört in den `finally`-Pfad und greift auch nach einem Absturz des Agenten-Dienstes (Abschnitt 8.7).

### 17.3 Umsetzung im GUI

Das Panel-, Toast- und Drawer-Vokabular existiert bereits (`openPanel`, `toast`, `quickCmd`, der Server-Log-Drawer). Die neuen Flächen folgen diesen Mustern und derselben Palette (`--red #ff1a1a`, `--green #33ff33`, `--orange #ff6600` für Agent-Herkunft, `--cyan #33ccff` für Operator-Herkunft).

Da `_OPERATOR_HTML` ein 5.388-zeiliges String-Literal ist, werden die neuen JS- und CSS-Anteile als **separate Dateien unter `software/c2/static/`** ausgeliefert und per `<script src>` eingebunden. `/static/<path:filename>` existiert bereits. Das hält die Änderung am String-Literal auf wenige Zeilen.

Polling folgt der bestehenden Konvention (`fetch` + `setInterval`), kein WebSocket: Agent-Stream 1,5 s, Drawer-Status 2 s, Approval-Prüfung 1,5 s.

---

## 18. Auslieferung

### Netzwerk

`docker-compose.yml` fährt `raccoon-c2` mit `network_mode: host` (nötig für Responder und das Relay-Tooling mit `NET_RAW`/`NET_ADMIN`). Es gibt deshalb **kein Compose-Netz** für Service-Namen.

- Der Agent-Dienst läuft ebenfalls im Host-Netz und bindet auf **`127.0.0.1:8099`**.
- `AGENT_URL` ist damit `http://127.0.0.1:8099` — nicht von außen erreichbar, kein veröffentlichter Port.
- Alternativ off-box: `AGENT_URL` zeigt auf einen anderen Host, dann ist TLS für diesen Hop Pflicht.

### Authentifizierung

Zwei getrennte Credentials:

- **C2 → Agent:** eigenes Token `RACCOON_AGENT_TOKEN`, geprüft mit `hmac.compare_digest`. Geht **nicht** den Weg über `GET /`.
- **Agent → C2:** der Operator-Token. Das setzt voraus, dass `RACCOON_TOKEN` in der Auslieferung **fest vorgegeben** ist statt beim Start generiert zu werden — sonst kennt der Agent ihn nicht. Agent-Requests tragen einen eigenen `User-Agent`, damit sie im Server-Log unterscheidbar sind.
- Gegen das selbstsignierte C2-Zertifikat verifiziert der Agent nicht, oder gegen einen konfigurierten Fingerprint-Pin.

### Images

- **Zweites Dockerfile** `software/agent/Dockerfile` mit **Repo-Root als Build-Kontext** — das bestehende `software/c2/Dockerfile` hat `software/c2/` als Kontext und kann `software/agent/` nicht sehen.
- Das Agent-Image ist schlank: Python, `aiohttp`, `anthropic`, `openai`, `PyYAML`, `croniter`. **Kein** Offensive-Arsenal — der Agent ruft es über die C2-API auf.
- Das C2-Image bleibt unverändert bis auf die COPY-Liste.
- Das **Box-Image** (`software/setup/build_image.sh`) bekommt die Wifi-Pakete aus Abschnitt 16.

### Konfiguration

Neuer `agent:`-Block in `configs/raccoon.yaml`, konsistent mit dem Repo (keine TOML — `tomllib` fehlt in 3.9). API-Keys ausschließlich über Umgebungsvariablen oder eine `0600`-Datei.

`start_server.sh` startet den Agent-Dienst optional mit.

---

## 19. Betrieb ohne LLM und Rückwärtskompatibilität

Harte Anforderung aus Ziel 7: **wer den Agenten nicht nutzt, darf von diesem Projekt nichts merken.** Das betrifft vier Ebenen, und jede bekommt eine eigene Zusicherung.

### 19.1 Drei Abstufungen des Fehlens

| Zustand | Verhalten |
|---|---|
| **Agent-Dienst läuft nicht** | C2 startet und arbeitet vollständig. `/api/ai/*` liefert `503` mit `{"error":"agent service unavailable"}`. Keine Exception, kein Stacktrace, keine Verzögerung im Beacon-Handling. |
| **Agent-Dienst läuft, kein Anbieter konfiguriert** | Dienst startet, Datenbank wird angelegt, `GET /api/ai/status` liefert `{"available": false, "reason": "no provider configured"}`. Kampagnenstart wird mit derselben Begründung abgelehnt, statt in einen Fehler zu laufen. |
| **Anbieter konfiguriert, aber nicht erreichbar** | Kampagnenstart schlägt mit lesbarer Meldung fehl, Run wird auf `failed` gesetzt, Beacon-Intervall zurückgesetzt. Bereits laufende Kampagnen brechen kontrolliert ab. |

Der Agent-Dienst ist in `docker-compose.yml` ein **eigener Service ohne `depends_on` in Richtung C2** und umgekehrt. Keiner der beiden wartet auf den anderen.

### 19.2 Das GUI bleibt funktionsfähig

Der kritische Pfad: `_OPERATOR_HTML` lädt die neuen Flächen über `<script src="/static/agent.js">`. Daraus folgt:

- **Die Agenten-Oberfläche wird erst aufgebaut, nachdem `GET /api/ai/status` geantwortet hat.** Antwortet er `503` oder `available: false`, wird der „Automated Attack"-Knopf **ausgegraut mit Tooltip-Begründung** gerendert — nicht versteckt, damit der Operator weiß, dass die Funktion existiert und warum sie nicht geht.
- Jeder `fetch` auf `/api/ai/*` ist in `try/catch`; ein Fehlschlag darf keine laufenden `setInterval`-Schleifen des bestehenden GUI abbrechen.
- Schlägt das Laden von `agent.js` selbst fehl (Datei fehlt, 404), bleibt das GUI vollständig bedienbar. Der Knopf wird deshalb **aus `agent.js` heraus eingefügt**, nicht statisch ins HTML-Literal geschrieben.
- Die Status-Abfrage läuft einmal beim Laden und danach nur, wenn der Operator den Knopf drückt — kein Dauer-Polling gegen einen Dienst, der nicht da ist.

### 19.3 Die Server-Änderungen sind einzeln additiv

Jede der sechs Änderungen aus Abschnitt 7.2 muss **für sich** verhaltensneutral sein, wenn kein Agent existiert:

| Änderung | Neutralität |
|---|---|
| Proxy-Routen | neue Pfade, berühren keinen bestehenden Endpoint |
| Task-Lanes | `lane` hat die Vorbelegung `"operator"`; bei ausschließlich Operator-Tasks ist die Auswahlreihenfolge identisch zum heutigen `queue.pop(0)` |
| Task-Batching | greift nur bei `caps` enthält `"batch"`; Beacons ohne diese Meldung bekommen unverändert ein einzelnes Task-Dict |
| `tool_runs` | der parameterlose Result-Endpoint liefert weiter den jüngsten Operator-Lauf; das bestehende GUI braucht keine Änderung |
| argv-Form | additiv; die String-Form bleibt unverändert inklusive `shell=True` |
| `phase`-Felder | nullable |

### 19.4 Beacon und Box bleiben kompatibel

- **Neuer Beacon gegen alten Server:** die `caps`-Meldung ist ein zusätzliches Feld im `register`-Payload. `_handle_register` ignoriert unbekannte Felder — ein neuer Beacon funktioniert gegen einen nicht aktualisierten Server.
- **Alter Beacon gegen neuen Server:** keine `caps` gemeldet heißt kein Batching, keine `wire`- und `wifi`-Tools. Der Beacon läuft unverändert.
- **Neue Kommandos** (`wire …`, `wifi …`) sind zusätzliche Zweige im bestehenden Dispatcher. Ein Beacon ohne sie antwortet wie bisher mit `Unknown command: …` — bereits vorhandenes Verhalten.
- **Die Box** ohne `agent:`-Block verhält sich identisch zu heute, inklusive Sliver-Vorrang (Abschnitt 5.2).
- Die Wifi-Pakete im Box-Image sind zusätzliche Pakete; ohne Nutzung ändern sie nichts am Verhalten. Wer das Image nicht neu baut, verliert nur die Wifi-Kette.

### 19.5 Keine neuen Pflicht-Abhängigkeiten im C2

`server.py` darf **nichts** aus `software/agent/` importieren. Die Kopplung läuft ausschließlich über HTTP. Konkret heißt das: `anthropic`, `openai`, `aiohttp` und `croniter` sind Abhängigkeiten des Agent-Images, nicht des C2-Images. Ein C2-Container ohne diese Pakete muss vollständig funktionieren.

Der Proxy in `server.py` nutzt deshalb `urllib` aus der Standardbibliothek oder eine bereits vorhandene Abhängigkeit — keine neue.

---

## 20. Tests

Konvention des Repos: stdlib `unittest`, Dateien unter `software/tests/`, ausführbar per `python -m unittest …`. Ein Mock-Modell mit Antwortwarteschlange ersetzt jeden Netzzugriff zum LLM; keine Live-API-Tests im Standardlauf.

| Bereich | Prüfung |
|---|---|
| `safety` | Metazeichen · Stufe-1-Liste mit und ohne `sudo` und mit absoluten Pfaden · Scan-Limit-Umschreibung (einfügen, bestehendes `-T5` entfernen, `netdiscover -c 1` nicht doppeln) · Deauth-Grenzen und Abkühlung · Uplink-Interface-Schutz · Skriptzeilen-Prüfung beim Speichern **und** Ausführen · Exploitation-Block bei abgeschalteter Phase 5 |
| `safety` Scope | fail-closed: Einzel-IP, CIDR, beide Bereichsformen, Hostname mit und ohne Fund-Zuordnung, Zieldatei-Argument wird abgelehnt, Denylist gewinnt gegen Allowlist |
| `safety` Risikotabelle | Prior-Werte · LLM-Korrektur wird auf ±0.2 geklammert · unbekannte Aktion fällt auf konservativen Prior |
| `gate` | erlaubt / abgelehnt / Timeout · EV-Schiedsrichter positiv und negativ · Stufe-1 ist auch im Full-Auto nicht erlaubbar · P(detect)-Nachführung nach 0, 1, 3 Detections · Detection-Budget bricht ab |
| `llm/loop` | Tool-Call → Ergebnis → Text · Turn-Budget-Erschöpfung · Werkzeugfehler als Wert · Text-Protokoll-Fallback · Kürzung zeichenweise bei Nicht-ASCII |
| `orchestrator` | Dispatch gibt Executor-Ergebnis zurück · paralleles Dispatch liefert beide Abschnitte · `Semaphore(1)` serialisiert ohne Deadlock · abgestürzter Executor liefert `[ERROR]` statt Exception · Task-Datensatz wird aktualisiert · `set_phase` schreibt Phase |
| `orchestrator` Lebenszyklus | Pause lässt laufende Executors zu Ende · Resume mit frischem Turn-Budget · Intervall-Rücksetzer bei `completed`/`failed`/`aborted`, **nicht** bei `paused` · Waisen-Erkennung beim Dienststart |
| `executor/beacon` | Task mit `lane="agent"` · Polling bis Ergebnis · Timeout-Verhalten |
| `executor/server_tool` | argv-Form · String-Form wird verweigert · Timeout behält Teilausgabe · werkzeugspezifisches Timeout greift über den Basenamen, auch bei `sudo` und absolutem Pfad |
| `store` | Schema-Anlage · FTS5-Rückfall auf `LIKE` · Verfallslauf · Verstärkungsdeckel bei 5.0 · Scheduler-Überlappungssperre |
| `wire` | Parser gegen aufgezeichnete pcaps: Host-Zusammenfassung, Credential-Extraktion je Protokoll, DNS · GPG-verschlüsselter Mitschnitt wird übersprungen |
| `wifi` | Adaptererkennung gegen gefälschtes sysfs (alle vier Zustände) · Monitor-Mode-Wiederherstellung auch bei Exception · airodump-CSV-Parser inklusive fehlerhafter Zeilen · `KEY FOUND!`-Parser · `1 handshake`-Parser · **alles oberhalb `wifi:scan` gegen Mocks, als solche markiert** |
| `server.py` | Lane-Vorrang (Operator vor Agent) · Batching nur bei `caps: ["batch"]`, alte Beacons bekommen ein einzelnes Task-Dict · `tool_runs` isoliert parallele Läufe · alter Result-Endpoint liefert nur Operator-Läufe · Proxy liefert `503` ohne Agent-Dienst |
| Integration | Kampagne gegen einen echten lokalen Beacon mit Mock-Modell: Run angelegt, Tasks dispatcht, Findings gespeichert, Phase gesetzt, Run abgeschlossen, Intervall zurückgesetzt |
| **Status quo** | **Eigene Testgruppe, muss ohne jede Agenten-Komponente grün sein:** die bestehende Suite (`test_c2_server.py`, `test_beacon.py`) läuft unverändert durch · C2 startet ohne `AGENT_URL` · `/api/ai/*` liefert `503` statt zu werfen · Task-Auswahl bei ausschließlich Operator-Tasks ist identisch zum heutigen Verhalten · alter Beacon ohne `caps` bekommt ein einzelnes Task-Dict · neuer Beacon mit `caps` registriert sich gegen einen Server ohne Lane-Unterstützung · parameterloser Result-Endpoint liefert den jüngsten Operator-Lauf · `server.py` importiert nichts aus `software/agent/` (per Quelltext-Prüfung) · `main.py` ohne `agent:`-Block verhält sich wie heute |

---

## 21. Was dem Umsetzenden überlassen bleibt

- Interne Modulaufteilung und Funktionssignaturen innerhalb der vorgegebenen Paketstruktur.
- Konkrete JSON-Schemata der Tool-Parameter (Eugenes Schemata sind eine gute Vorlage, keine Vorschrift).
- Wortlaut der Preambles, solange die in Abschnitt 12 genannten Inhalte abgedeckt sind.
- Vollständigkeit der Risikotabelle in Abschnitt 10.5 — die genannten Zeilen sind Beispiele, die Struktur ist festgelegt.
- Vollständigkeit der Detection-Muster in Abschnitt 10.6.
- Poll-Intervalle und Timeouts im Detail, solange die Größenordnungen eingehalten werden.
- Aufteilung der GUI-Dateien unter `static/` und das konkrete DOM.
- Ob der Proxy in `server.py` mit `urllib` oder einer bereits vorhandenen Abhängigkeit arbeitet — eine **neue** Abhängigkeit im C2-Image ist ausgeschlossen (Abschnitt 19.5).
- Wie die Fähigkeitsstufe eines Modells konkret ermittelt wird (Metadaten, Allowlist, Heuristik) — nur die drei Stufen und ihre Auswirkungen sind festgelegt.
- Reihenfolge der Umsetzung, mit einer Ausnahme: die Agenten-Schicht (Abschnitte 7–14) sollte vor den Teilprojekten Wire Intel und Wifi stehen, weil beide gegen ihre Capability-Mechanik gebaut werden.

---

## 22. Offene Punkte

Keine. Die Entscheidungen aus dem Gespräch und aus der Reviewer-Runde sind in den Abschnitten 5.2, 5.3, 8.6, 8.7, 9, 10.4, 10.5, 10.6, 15, 16, 18 und 19 festgehalten.

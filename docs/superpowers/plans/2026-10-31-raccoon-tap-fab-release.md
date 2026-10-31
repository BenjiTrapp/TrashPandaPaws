# Raccoon Tap — Fertigungsfreigabe: Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `hardware/kicad/raccoon-tap.kicad_pcb` wird von einem platzierten, unrouteten Entwurf zu einem gerouteten, DRC-sauberen 4-Layer-Board mit Fertigungsdaten, die bei PCBWay bestellbar sind.

**Architecture:** `netlist.yaml` bleibt die Quelle der Wahrheit für Konnektivität; Schaltplan, BOM und PCB-Platzierung werden daraus generiert. Ab Task 9 ist die Leitungsgeometrie im PCB ein gepflegtes Artefakt und wird nicht mehr neu erzeugt. Verifikation läuft durchgehend über `kicad-cli` (ERC/DRC, die Autorität), die repo-eigenen Prüfskripte unter `hardware/tests/` und kicad-happy (Signalintegrität, EMC, Thermik, Fab-Gate).

**Tech Stack:** KiCad 10.0.6 (`/opt/homebrew/bin/kicad-cli`), `pcbnew`-Bindings unter KiCads gebündeltem Python 3.9, Python 3.12 für kicad-happy (System-`python3` ist 3.9.6 und zu alt), PyYAML, kicad-happy v2.

**Spec:** `docs/superpowers/specs/2026-10-30-raccoon-tap-fab-release-design.md`

## Global Constraints

- Fertiger ist **PCBWay**, Beschaffung MPN-basiert. Bare Board plus **Teilbestückung genau eines Bauteils (U3)**.
- Der Operator lötet mit **Lötkolben und Flussmittel**, keine Schablone, keine Heißluft. Passive auf 0603 heben, wo Platz und Signalintegrität es zulassen — **ausgenommen C19/C20 und die Entkopplungskondensatoren direkt an U3**.
- **4 Lagen, 1,6 mm, 1 oz außen.** Belegung: `F.Cu` Signale, `In1.Cu` massiv GND, `In2.Cu` Power, `B.Cu` Signale plus GND-Pour.
- Impedanz: **USB 3.0 und USB 2.0 90 Ω differenziell, MDI 100 Ω differenziell**, beide referenziert auf `In1`.
- Längenmatching: **USB 3.0 ≤ 2 mm, MDI ≤ 5 mm.**
- **Die `In1`-Massefläche wird unter keinem Differenzialpaar unterbrochen.** Jedes Paar behält über seine gesamte Länge eine durchgehende Referenz.
- Boardmaß 58 × 36 mm, **darf wachsen**. Dicke, Kupferstärke und Impedanzkontrolle bleiben unangetastet.
- **Pin-Nummern von U3 werden nie abgeleitet.** Nur Datenblatt oder zwei unabhängige übereinstimmende Quellen (Spec §5.3). Olimex zählt nicht: dort sitzt der RTL8153**VC** im QFN-48.
- `netlist.yaml` ist maßgeblich für Konnektivität. Jede Konnektivitätsänderung geht dort hinein und wird über die Generatoren gezogen, **niemals von Hand in Schaltplan, BOM oder PCB**.
- Ab Task 9 ist die PCB-Geometrie eingefroren. `gen_pcb.py` darf danach nicht mehr auf das Board laufen.
- Planungsannahme **5 Prototypen**. Preise werden vor jeder Bestellung vorgelegt.
- Obergrenze **drei EMC-Iterationen pro Differenzialpaar**, danach Halt und Übergabe des platzierten Boards.
- Keine Erfolgsmeldung ohne die Ausgabe des Prüfkommandos.

Interpreter, wörtlich:

```
KIPY=/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3
KH=/opt/homebrew/bin/python3.12
```

## Review Focus

Fehlermodi, die die Spec impliziert, die aber kein Arbeitspaket von sich aus prüft. Jede Zeile bekommt ihren Test im zuständigen Task.

1. **Ein erneuter `gen_pcb.py`-Lauf nach dem Einfrieren vernichtet das Routing** — die Datei wird mit `NewBoard()` neu angelegt, es gibt keine Rückfrage. Test in Task 9.
2. **Platzhalter-Geometrie in den Netzklassen erreicht die Fertigung** — die Impedanzziele wären dann nur Absicht, nicht Eigenschaft. Test in Task 7.
3. **Eine BOM-Zeile ohne Teilenummer oder mit EOL-Teil geht in die Bestellung** — PCBWay beschafft MPN-basiert, eine leere Zelle wird stillschweigend nicht bestellt. Test in Task 6.
4. **Gerber werden aus einem Board exportiert, das die DRC nicht besteht, oder sind älter als das PCB** — ein veralteter Satz sieht wie ein gültiger aus. Test in Task 11.
5. **Das Board bricht beim Einstecken den USB-Port des Hosts ein** — die Bulk-Kapazität an VBUS übersteigt die von der USB-Spezifikation erlaubten 10 µF. Test in Task 5.

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `.opencode/opencode.json` | *neu* — zeigt opencodes Skill-Loader auf das vendorierte kicad-happy |
| `vendor/kicad-happy/` | *neu* — vendorierte Analysewerkzeuge, per `git subtree --squash` |
| `hardware/review/` | *neu* — committete Analyseberichte, Basis und Folgestände |
| `hardware/tests/check_kicad.py` | Strukturprüfungen; wird auf KiCad-10-Netzformat und das Tap-Board umgestellt und um Konnektivitäts- und Freigabeprüfungen erweitert |
| `hardware/tests/check_fab_release.py` | *neu* — Torprüfungen aus Review Focus 2, 3 und 4 |
| `hardware/netlist.yaml` | Quelle der Wahrheit: Komponenten, Netze, `design_notes`, `meta` |
| `hardware/tools/gen_pcb.py` | Platzierung, Stackup, Zonen, Vias, Boardumriss; bekommt Einfrier-Schutz |
| `hardware/tools/route_pcb.py` | *neu* — setzt Leiterbahnen und Differenzialpaare über `pcbnew` |
| `hardware/kicad/raccoon-tap.kicad_pro` | Netzklassen mit der gerechneten Impedanzgeometrie |
| `hardware/kicad/raccoon-tap.kicad_pcb` | ab Task 9 gepflegtes Artefakt |
| `hardware/fab/` | *neu* — Gerber, Bohrdatei, CPL, Fertigungsnotiz, Bestellanleitung |
| `hardware/OPEN_QUESTIONS.md`, `hardware/design-guide.md` | Dokumentation nachgezogen |

---

## Task 1: kicad-happy im Repo verankern

**Files:**
- Create: `.opencode/opencode.json`
- Create: `vendor/kicad-happy/` (per `git subtree`)
- Modify: `hardware/OPEN_QUESTIONS.md` (Abschnitt `## Tooling`)

**Interfaces:**
- Produces: die Skript-Pfade `vendor/kicad-happy/skills/<skill>/scripts/<script>.py`, die alle folgenden Tasks aufrufen, und die Interpreter-Variablen `KH` und `KIPY`.

- [ ] **Step 1: Prüfen, dass `.gitignore` das Zielverzeichnis nicht schluckt**

Run: `git check-ignore -v vendor/kicad-happy || echo "nicht ignoriert"`
Expected: `nicht ignoriert`

- [ ] **Step 2: Subtree hinzufügen**

```bash
git subtree add --prefix vendor/kicad-happy \
  https://github.com/aklofas/kicad-happy.git v2 --squash
```

- [ ] **Step 3: Konfiguration schreiben**

`.opencode/opencode.json` mit `$schema` auf `https://opencode.ai/config.json` und `"skills": { "paths": ["./vendor/kicad-happy/skills"] }`.

- [ ] **Step 4: Verifizieren, dass die Skripte unter Python 3.12 laufen**

Run: `$KH vendor/kicad-happy/skills/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output /tmp/t1.json`
Expected: `Written to /tmp/t1.json`, Exit 0. Dann zusätzlich `python3 vendor/kicad-happy/skills/kicad/scripts/analyze_schematic.py --help` laufen lassen und bestätigen, dass System-Python 3.9 scheitert — das belegt, warum `KH` nötig ist.

- [ ] **Step 5: Tooling-Notiz ergänzen**

In `hardware/OPEN_QUESTIONS.md` unter `## Tooling` eintragen: womit analysiert wird, der gepinnte Upstream-Stand (`v2`), das Upgrade-Kommando `git subtree pull --prefix vendor/kicad-happy ... --squash`, und dass `KH` zu verwenden ist, weil System-Python 3.9.6 unter dem Mindestmaß liegt.

- [ ] **Step 6: Commit**

```bash
git add .opencode/opencode.json hardware/OPEN_QUESTIONS.md
git commit -m "Anchor kicad-happy in the repo and record how to run it"
```

---

## Task 2: Basis-Review erheben und committen

**Files:**
- Create: `hardware/review/2026-10-31-baseline/` (JSON-Ausgaben und Textbericht)

**Interfaces:**
- Produces: `hardware/review/2026-10-31-baseline/schematic.json` und `pcb.json`, die Folge-Tasks als Vergleichsbasis heranziehen; die Kennzahlentabelle in `README.md` desselben Verzeichnisses.

- [ ] **Step 1: Analysen laufen lassen**

```bash
mkdir -p hardware/review/2026-10-31-baseline
R=hardware/review/2026-10-31-baseline
S=vendor/kicad-happy/skills
$KH $S/kicad/scripts/analyze_schematic.py hardware/kicad/raccoon-tap.kicad_sch --output $R/schematic.json
$KH $S/kicad/scripts/analyze_pcb.py hardware/kicad/raccoon-tap.kicad_pcb --full --schematic $R/schematic.json --stage layout --output $R/pcb.json
$KH $S/kicad/scripts/cross_analysis.py -s $R/schematic.json -p $R/pcb.json --output $R/cross.json
$KH $S/emc/scripts/analyze_emc.py -s $R/schematic.json -p $R/pcb.json --output $R/emc.json
$KH $S/kicad/scripts/analyze_thermal.py -s $R/schematic.json -p $R/pcb.json --output $R/thermal.json
```

- [ ] **Step 2: KiCads eigene Prüfungen daneben erheben**

```bash
kicad-cli sch erc --severity-all --output erc.rpt hardware/kicad/raccoon-tap.kicad_sch
kicad-cli pcb drc --severity-all --output drc.rpt hardware/kicad/raccoon-tap.kicad_pcb
```

- [ ] **Step 3: Kennzahlen festhalten**

`hardware/review/2026-10-31-baseline/README.md` mit einer Tabelle: Footprints, Leiterbahnsegmente, Vias, Zonen, unverbundene Elemente, DRC-Fehler, DRC-Warnungen, ERC-Fehler, EMC-Risikoscore, höchste Sperrschichttemperatur. Dazu eine Liste: welche der in Spec §7.4 gelisteten Punkte kicad-happy selbständig gefunden hat und welche es übersehen hat. Die zweite Liste ist das Ergebnis, auf das es hier ankommt — sie sagt, wie weit dem Werkzeug in Task 10 zu trauen ist.

- [ ] **Step 4: Commit**

```bash
git add hardware/review/2026-10-31-baseline
git commit -m "Record the pre-routing analysis baseline"
```

---

## Task 3: Datenblatt-Gate für U3

Dieses Task ist ein Tor. Fällt es auf Stufe 3, endet der Plan hier und Tasks 5 bis 12 werden nicht ausgeführt.

**Files:**
- Create: `hardware/datasheets/` (bezogene PDFs, falls vorhanden)
- Create: `hardware/review/u3-pinout-verdict.md`

**Interfaces:**
- Produces: `hardware/review/u3-pinout-verdict.md` mit einer Pin-Tabelle für alle 40 Pins plus Pad, jede Zeile mit Quellenangabe, und einem Urteil `belegt` oder `nicht belegt`. Task 5 konsumiert diese Tabelle.

- [ ] **Step 1: Stufe 1 — Datenblatt beschaffen**

Den `datasheets`-Skill und die Distributor-Skills (`lcsc`, `mouser`, `digikey`, `element14`) auf `RTL8153B-VB-CG` ansetzen. Dazu gezielte Suche nach Revision 1.4 / Track ID JATR-8275-15. Jeder bezogene PDF wird gegen die erwartete Teilenummer verifiziert, bevor er verwendet wird.

- [ ] **Step 2: Bei Erfolg — Pinout extrahieren**

Run: `$KH vendor/kicad-happy/skills/datasheets/scripts/extract_datasheet.py <pdf> --output hardware/datasheets/extracted/RTL8153B-VB-CG.json`
Expected: strukturierte Pinout-Sektion mit 40 Pins. Fehlt die Pinout-Sektion oder ist ihr Quality-Score niedrig, gilt Stufe 1 als gescheitert.

- [ ] **Step 3: Bei Misserfolg — Stufe 2, zwei unabhängige Quellen**

Eine von `design-guide.md` §2.1 **unabhängige** zweite Quelle suchen: ein veröffentlichtes Design mit exakt dem RTL8153B-VB-CG im QFN-40, oder eine Pinout-Zeichnung eines Distributors. Olimex ist ausgeschlossen (QFN-48, VC-Variante). Die Quelle muss die Variante ausdrücklich nennen.

- [ ] **Step 4: Urteil schreiben**

`hardware/review/u3-pinout-verdict.md`: Tabelle aller 40 Pins plus Thermal-Pad, je Zeile Name, Nummer und Quelle. Für die neun in Spec §7.4 genannten Versorgungs- und Reglerpins (`AVDD10`, `AVDD33`, `DVDD10`, `DVDD33`, `VDD5`, `REGOUT`, `DVDD10_UPS`, `RSET`, `GND`) ist die Quellenangabe Pflicht. Abschließend der Widerspruch zwischen `design-guide.md` §2.1 und `OPEN_QUESTIONS.md` 3b: aufgelöst mit Begründung, oder als weiterhin offen markiert.

- [ ] **Step 5: Tor auswerten**

Lautet das Urteil `nicht belegt`, dann: Liste exakt der Pins ohne Belegung in das Urteilsdokument, Spec §5.3 Stufe 3 im Dokument zitieren, committen, **und den Plan hier beenden.** Keine Platzierungsänderung, kein Routing, keine Bestellung.

- [ ] **Step 6: Commit**

```bash
git add hardware/datasheets hardware/review/u3-pinout-verdict.md
git commit -m "Verify or refute the RTL8153B-VB-CG pinout against a real source"
```

---

## Task 4: `check_kicad.py` auf KiCad 10 und das Tap-Board umstellen

Unabhängig von Task 3 und parallel ausführbar.

**Files:**
- Modify: `hardware/tests/check_kicad.py`

**Interfaces:**
- Produces: `check_kicad.py` prüft ab jetzt `raccoon-tap.*`; die Funktion `check_pcb_nets(pcb_text) -> list[str]` akzeptiert das namensbasierte KiCad-10-Padformat; neu `check_pcb_connectivity(pcb_text, netlist) -> list[str]`, von Task 10 konsumiert.

- [ ] **Step 1: Den fehlschlagenden Test schreiben**

In `hardware/tests/` einen Test ergänzen, der `check_kicad.py` gegen `raccoon-tap.kicad_pcb` laufen lässt und erwartet, dass die Netzprüfung **nicht** beanstandet:

```python
def test_kicad10_named_pad_nets_are_accepted():
    text = (HARDWARE / "kicad" / "raccoon-tap.kicad_pcb").read_text()
    assert check_pcb_nets(text) == []
```

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_kicad.py -v`
Expected: FAIL — die derzeitige Regel verlangt eine Netztabelle mit Integer-IDs, die KiCad 10 nicht mehr schreibt.

- [ ] **Step 3: Die Netzprüfung auf beide Formate umstellen**

`check_pcb_nets` erkennt das Format und prüft dann passend: KiCad-9-Form (Netztabelle vorhanden) wie bisher gegen Integer-IDs; KiCad-10-Form (`(net "NAME")` im Pad, keine Tabelle) dagegen, dass jeder Pad-Netzname in `netlist.yaml` vorkommt und jede Zone einen Netznamen trägt. `SCH`, `PCB` und `BOM` am Modulkopf auf `raccoon-tap` umstellen; die Konstante `LEGACY_PCB` bleibt für das Archivboard erhalten, wird aber nicht mehr geprüft.

- [ ] **Step 4: Konnektivitätsprüfung ergänzen**

`check_pcb_connectivity(pcb_text, netlist)` prüft für jedes Netz in `netlist.yaml`, dass die Menge der Pads mit diesem Netznamen im PCB genau den Endpunkten im Netlist entspricht. Das ist der Ersatz für die Reproduzierbarkeit, die mit dem Einfrieren in Task 9 verloren geht.

- [ ] **Step 5: Tests laufen lassen**

Run: `python3 hardware/tests/check_kicad.py -v && python3 hardware/tests/check_netlist.py -v`
Expected: beide Exit 0.

- [ ] **Step 6: Commit**

```bash
git add hardware/tests/check_kicad.py
git commit -m "Teach check_kicad.py the KiCad 10 net format and point it at the tap board"
```

---

## Task 5: Datenblatt-abhängige Punkte in `netlist.yaml` schließen

Setzt Task 3 mit Urteil `belegt` voraus.

**Files:**
- Modify: `hardware/netlist.yaml`
- Modify: `hardware/design-guide.md` (§2.1, falls das Urteil sie korrigiert)
- Test: `hardware/tests/check_netlist.py` (bestehend), `hardware/tests/check_fab_release.py` (neu)

**Interfaces:**
- Consumes: die Pin-Tabelle aus `hardware/review/u3-pinout-verdict.md`.
- Produces: `netlist.yaml` mit belegten U3-Pins, ausgewähltem Quarz samt berechneten `C19`/`C20`, entschiedener `SHIELD`-Strategie und bestätigter LED-Richtung.

- [ ] **Step 1: Den fehlschlagenden Test für Review Focus 5 schreiben**

`hardware/tests/check_fab_release.py` neu anlegen mit:

```python
def test_vbus_bulk_capacitance_within_usb_limit():
    total_uf = sum_bulk_capacitance(load_netlist(), rail="+5V")
    assert total_uf <= 10.0, f"{total_uf} uF an VBUS, USB erlaubt 10 uF"
```

`sum_bulk_capacitance(netlist, rail) -> float` summiert die Kapazität aller Kondensatoren, die am genannten Rail hängen, in Mikrofarad.

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: FAIL mit etwa `21.2 uF an VBUS, USB erlaubt 10 uF`.

- [ ] **Step 3: U3-Pins aus dem Urteil übernehmen**

Jede Pin-Nummer in `netlist.yaml` gegen die Tabelle aus Task 3 abgleichen und bei Abweichung korrigieren. Die Provenance-Notiz jeder geänderten Zeile auf die in Task 3 belegte Quelle setzen. Widersprüchliche Angaben in `design-guide.md` §2.1 im selben Zug richtigstellen.

- [ ] **Step 4: Quarz auswählen und Lastkapazitäten berechnen**

25 MHz, Gehäuse passend zum vorhandenen Platzhalter-Footprint oder Footprint anpassen. `C19`/`C20` aus der Lastkapazität des gewählten Quarzes rechnen, nicht aus dem 39-pF-Platzhalter übernehmen. Rechnung und gewählte Teilenummer als Provenance-Notiz eintragen und die `TBD`-Markierung entfernen.

- [ ] **Step 5: LED-Richtung, USB-3.0-Crossover und `SHIELD` festschreiben**

LED-Stromrichtung aus [RTL-DS] 6.2 bestätigen; senken die Pins nicht, wandern die Widerstände auf die Kathodenseite. SSTX/SSRX-Benennung gegen das Würth-692112030100-Datenblatt prüfen und `design_notes.usb3_crossover` von „zu verifizieren" auf das Ergebnis umschreiben. `design_notes.shield_tie` auf die gewählte Strategie festlegen (Einpunkt-Masse direkt oder 1 nF ∥ 1 MΩ) mit Begründung.

- [ ] **Step 6: Feed-Forward-Pad, U3-Footprint und `meta` nachziehen**

An `R5`/`R6` ein DNP-Pad für einen Feed-Forward-Kondensator vorsehen oder das Weglassen in `design_notes` begründen. Bestätigen, dass `Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` in der installierten KiCad-Bibliothek auflöst — `OPEN_QUESTIONS.md` führt das als ungeprüft. Run: `kicad-cli fp list-footprints` oder gleichwertig, Expected: der Name ist enthalten. Löst er nicht auf, Footprint ins projekteigene `raccoon.pretty` übernehmen. `meta.revision` erhöhen.

- [ ] **Step 7: Prüfungen laufen lassen**

Run: `python3 hardware/tests/check_netlist.py -v`
Expected: Exit 0. Der Test aus Step 1 schlägt weiterhin fehl — er wird in Task 6 grün.

- [ ] **Step 8: Commit**

```bash
git add hardware/netlist.yaml hardware/design-guide.md hardware/tests/check_fab_release.py
git commit -m "Close the datasheet-dependent open items in the netlist"
```

---

## Task 6: VBUS-Einschaltverhalten, ESD-Schutz, Messpunkte und BOM

**Files:**
- Modify: `hardware/netlist.yaml`
- Modify: `hardware/bom.csv` (erzeugt über `gen_bom.py`)
- Modify: `hardware/tests/check_fab_release.py`

**Interfaces:**
- Consumes: `sum_bulk_capacitance` aus Task 5.
- Produces: `check_mpn_coverage(bom_rows) -> list[str]`, von Task 11 konsumiert; der vollständige Bauteilesatz, den Task 8 platziert.

- [ ] **Step 1: Den fehlschlagenden Test für Review Focus 3 schreiben**

In `check_fab_release.py` ergänzen:

```python
def test_every_bom_row_has_a_part_number():
    assert check_mpn_coverage(load_bom()) == []
```

`check_mpn_coverage(bom_rows) -> list[str]` gibt für jede Zeile ohne Teilenummer eine Meldung mit Referenz und Wert zurück.

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: FAIL, zehn Meldungen plus der VBUS-Test aus Task 5.

- [ ] **Step 3: VBUS-Einschaltstrom begrenzen**

Bulk-Kapazität an `+5V` auf das von der USB-Spezifikation erlaubte Maß bringen und einen Load-Switch mit Soft-Start oder eine gleichwertige Einschaltstrombegrenzung in `netlist.yaml` aufnehmen. Gehäuse von Hand lötbar. Die Rechnung, die den Zielwert begründet, als `design_notes`-Eintrag.

- [ ] **Step 4: ESD-Schutz aufnehmen**

Auf `USB_DP`/`USB_DM` ein Standard-ESD-Array. Auf den SuperSpeed-Paaren nur Bauteile mit so geringer Kapazität, dass die 90-Ω-Strecke nicht verstimmt wird — die Grenzkapazität als Auswahlkriterium in `design_notes` festhalten. MDI bleibt ungeschützt, weil Magnetik und integrierte Bob-Smith-Terminierung in J2 das abdecken; das wird als bewusste Entscheidung notiert.

- [ ] **Step 5: Messpunkte vorsehen**

Testpads und je eine auftrennbare Serienbrücke in `+3V3` und `+1V0`, damit die auf den ersten Aufbau verschobenen Strommessungen durchführbar sind. Auslegungsstrom für `+3V3` als dokumentierte konservative Annahme in `design_notes.rail_currents` eintragen, mit der Rechnung und dem Hinweis, dass sie am ersten Aufbau zu prüfen ist.

- [ ] **Step 6: Teilenummern beschaffen**

Über die Distributor-Skills für jede Zeile ohne Teilenummer ein lieferbares Teil bestimmen: Teilenummer, Gehäuse, Preis, Verfügbarkeit, Lebenszyklus. Gehäuse auf 0603 heben, wo erlaubt. Lebenszyklusprüfung über **alle** Zeilen. Zusätzlich die Verfügbarkeit von `U3` selbst klären — Realtek vertreibt über eigene Kanäle — und festhalten, ob PCBWay beschaffen kann oder beigestellt werden muss.

- [ ] **Step 7: BOM erzeugen und Tests laufen lassen**

```bash
python3 hardware/tools/gen_bom.py
python3 hardware/tests/check_netlist.py -v
python3 hardware/tests/check_fab_release.py -v
```
Expected: alle Exit 0. Beide Tests aus Step 1 und Task 5 Step 1 sind jetzt grün.

- [ ] **Step 8: U3-Beschaffung vorlegen**

Quelle, Preis und Vorlaufzeit für `U3` sowie den Aufpreis für PCBWays Teilbestückung bei 5 Stück in `hardware/review/u3-sourcing.md` zusammenstellen. **Nichts bestellen.**

- [ ] **Step 9: Commit**

```bash
git add hardware/netlist.yaml hardware/bom.csv hardware/tests/check_fab_release.py hardware/review/u3-sourcing.md
git commit -m "Add inrush limiting, ESD protection and measurement points; complete the BOM"
```

---

## Task 7: Impedanzgeometrie von PCBWay in die Netzklassen

**Files:**
- Modify: `hardware/kicad/raccoon-tap.kicad_pro`
- Create: `hardware/fab/stackup-note.md`
- Modify: `hardware/tests/check_fab_release.py`

**Interfaces:**
- Produces: die Netzklassen `USB3` und `MDI` mit gerechneter Breite und Abstand; `hardware/fab/stackup-note.md`, von Task 11 der Bestellung beigelegt; `check_no_placeholder_geometry(pro_json, stackup_note) -> list[str]`.

- [ ] **Step 1: Den fehlschlagenden Test für Review Focus 2 schreiben**

```python
def test_diff_pair_geometry_is_calculated_not_placeholder():
    assert check_no_placeholder_geometry(load_pro(), load_stackup_note()) == []
```

Die Prüfung vergleicht `diff_pair_width` und `diff_pair_gap` der Klassen `USB3` und `MDI` gegen die in `hardware/fab/stackup-note.md` dokumentierten gerechneten Werte und beanstandet jede Abweichung sowie eine fehlende Notiz.

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: FAIL — `hardware/fab/stackup-note.md` existiert nicht.

- [ ] **Step 3: Stackup wählen und Geometrie rechnen**

PCBWays 4-Layer-1,6-mm-Aufbauten heranziehen, einen auswählen und mit ihrem Impedanzrechner die Breite/Abstand-Geometrie für 90 Ω und 100 Ω auf den tatsächlichen Kern- und Prepreg-Dicken bestimmen. Gewählter Aufbau, Dielektrikumsdicken, Eingabewerte, Ergebnis und Toleranz nach `hardware/fab/stackup-note.md`, dazu die Mindestbreitenregel des Impedanzservices.

- [ ] **Step 4: Platzbedarf prüfen**

Gegen die 58 × 36 mm und das 0,4-mm-Raster von U3 abschätzen, ob sieben Paare mit der gerechneten Geometrie unterzubringen sind. Wird es eng, Rangfolge aus Spec 11.8 anwenden: zuerst Board vergrößern, dann Führung umlegen. Reicht beides nicht, Halt mit Rückfrage. Das Ergebnis in der Notiz festhalten.

- [ ] **Step 5: Netzklassen setzen und Test laufen lassen**

Werte in `raccoon-tap.kicad_pro` eintragen.
Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: Exit 0.

- [ ] **Step 6: Commit**

```bash
git add hardware/kicad/raccoon-tap.kicad_pro hardware/fab/stackup-note.md hardware/tests/check_fab_release.py
git commit -m "Set diff-pair geometry from PCBWay's impedance calculator"
```

---

## Task 8: Platzierung überarbeiten und neue Basis erheben

**Files:**
- Modify: `hardware/tools/gen_pcb.py` (`PLACEMENT`, Boardumriss, Befestigungslöcher, Zonen)
- Modify: `hardware/kicad/raccoon-tap.kicad_pcb` (erzeugt)
- Create: `hardware/review/2026-10-31-placement/`

**Interfaces:**
- Consumes: den Bauteilesatz aus Task 6 und die Geometrie aus Task 7.
- Produces: das platzierte Board, auf dem Task 9 routet. Letzter Lauf von `gen_pcb.py` auf dieses Board.

- [ ] **Step 1: U3 drehen und die Nachbarschaft mitbewegen**

In `PLACEMENT` die Rotation von `U3` so setzen, dass die MDI-Pins 1–10 zu `J2` zeigen. Quarzblock (`Y1`, `C19`, `C20`) und Entkopplungsring mit der neuen Orientierung mitführen. Begründung als Kommentar an die Tabelle: in der alten Lage zeigten die MDI-Pins zum USB-Stecker und die Paare hätten das Gehäuse umlaufen und die SuperSpeed-Ausführung kreuzen müssen.

- [ ] **Step 2: Befestigung und Zugentlastung einbringen**

Zwei M2,5-Befestigungslöcher in den beiden Ecken fern des USB-Steckers, ausgerichtet auf die Befestigungspunkte des Pi 4, mit Sperrfläche und Masseanbindung. Zugentlastung für das RJ45-Kabel. Belegt wird der untere USB-3.0-Port, Lasche nach unten. Boardumriss anpassen, falls Task 7 eine Vergrößerung verlangt hat.

- [ ] **Step 3: Restliche Platzierungsarbeit**

Entkopplungskondensatoren an ihre Versorgungspins heranziehen; `C21` nah an die PHY-seitigen Mittelanzapfungen von `J2`; `J2` so orientieren, dass die RJ45-Öffnung zur Platinenkante zeigt; Buck-Hot-Loop um `U6` klein halten und den `R5`/`R6`-Teiler vom LX-Schaltknoten wegziehen; `U4` mit Kupferfläche für die Verlustleistung aus Task 6 Step 5 versehen; `In2` in `+5V`-, `+3V3`- und `+1V0`-Inseln aufteilen; die Vias unter dem Thermal-Pad von `U3` von der Rückseite abdecken.

- [ ] **Step 4: Board erzeugen**

Run: `$KIPY hardware/tools/gen_pcb.py`
Expected: Exit 0, alle Footprints geladen.

- [ ] **Step 5: Neue Basis erheben**

```bash
kicad-cli pcb drc --severity-all --output hardware/review/2026-10-31-placement/drc.rpt hardware/kicad/raccoon-tap.kicad_pcb
python3 hardware/tests/check_kicad.py -v
```
Expected: **0 DRC-Fehler**; Warnungen und unverbundene Elemente sind zulässig, weil noch nichts geroutet ist. `check_kicad.py` Exit 0. Steigt die Fehlerzahl über 0, hier bleiben und beheben — `OPEN_QUESTIONS.md` dokumentiert einen Fall, in dem eine Korrektur die DRC von 263 auf 269 getrieben hat.

- [ ] **Step 6: Commit**

```bash
git add hardware/tools/gen_pcb.py hardware/kicad/raccoon-tap.kicad_pcb hardware/review/2026-10-31-placement
git commit -m "Rotate U3 toward the MagJack, add mounting holes, split the power plane"
```

---

## Task 9: Routen

Ab dem ersten Commit dieses Tasks ist die PCB-Geometrie eingefroren.

**Files:**
- Create: `hardware/tools/route_pcb.py`
- Modify: `hardware/tools/gen_pcb.py` (Einfrier-Schutz)
- Modify: `hardware/kicad/raccoon-tap.kicad_pcb`

**Interfaces:**
- Produces: das geroutete Board. `route_pcb.py` stellt `route_pair(board, net_p, net_n, waypoints, layer)` und `route_net(board, net, waypoints, width, layer)` bereit.

- [ ] **Step 1: Den fehlschlagenden Test für Review Focus 1 schreiben**

In `hardware/tests/check_fab_release.py`:

```python
def test_gen_pcb_refuses_to_overwrite_a_routed_board():
    result = run_gen_pcb_on_routed_board()
    assert result.returncode != 0
    assert "geroutet" in result.stderr
```

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: FAIL — `gen_pcb.py` legt die Datei bedingungslos mit `NewBoard()` neu an.

- [ ] **Step 3: Einfrier-Schutz einbauen**

`gen_pcb.py` zählt vor dem Schreiben die Leiterbahnsegmente in der vorhandenen Zieldatei. Bei mehr als null bricht es mit nicht-null Exit und einer Meldung ab, die sagt, dass das Board geroutet ist und ein Lauf das Routing vernichten würde, und die `--force` als bewusste Ausnahme nennt. Den Docstring auf die Entscheidung aus Spec §6.3 umschreiben.

- [ ] **Step 4: Routing-Werkzeug bauen**

`hardware/tools/route_pcb.py` mit `pcbnew` unter `KIPY`: `route_net` legt `PCB_TRACK`-Segmente entlang übergebener Wegpunkte mit Breite und Lage; `route_pair` führt zwei Netze mit konstantem Abstand nach der Geometrie aus Task 7 und meldet die Längendifferenz zurück. Beide verweigern Segmente, die `In1` unter sich unterbrochen hätten, und melden das als Fehler statt es zu setzen.

- [ ] **Step 5: In der vorgegebenen Reihenfolge routen**

Nach absteigender Empfindlichkeit, und nach **jedem** Paar die EMC-Prüfung:

1. USB 3.0 TX und RX
2. MDI 0 bis 3
3. USB 2.0 D+/D−
4. Buck-Hot-Loop um `U6`
5. Versorgungen über die `In2`-Inseln
6. Niedergeschwindigkeitsnetze
7. Thermal-Pad von `U3` an `In1` stitchen und die Perimeter-Vias anbinden

Nach jedem Paar: `$KH vendor/kicad-happy/skills/emc/scripts/analyze_emc.py -s <sch.json> -p <pcb.json>` und prüfen, dass Skew innerhalb der Grenze liegt und keine Lücke in der Referenzfläche unter dem Paar gemeldet wird. **Drei Iterationen pro Paar sind die Obergrenze.** Danach Halt: platziertes Board plus Routing-Briefing übergeben, nicht weiter probieren.

- [ ] **Step 6: Tests laufen lassen**

```bash
kicad-cli pcb drc --severity-all --output /tmp/drc-routed.rpt hardware/kicad/raccoon-tap.kicad_pcb
python3 hardware/tests/check_fab_release.py -v
```
Expected: **0 DRC-Fehler und 0 unverbundene Elemente.** Die 41 vormals dangling Vias sind verschwunden, weil sie jetzt angebunden sind.

- [ ] **Step 7: Commit**

```bash
git add hardware/tools/route_pcb.py hardware/tools/gen_pcb.py hardware/kicad/raccoon-tap.kicad_pcb
git commit -m "Route the board and freeze the PCB against regeneration"
```

---

## Task 10: Verifikationskette

**Files:**
- Create: `hardware/review/2026-10-31-routed/`
- Modify: `hardware/tests/run_all.sh`

**Interfaces:**
- Produces: `hardware/review/2026-10-31-routed/` mit allen Ausgaben; `run_all.sh` ruft die Hardware-Prüfungen mit auf.

- [ ] **Step 1: Die Kette laufen lassen und jede Ausgabe ablegen**

| Prüfung | Kriterium |
|---|---|
| `kicad-cli pcb drc --severity-all` | 0 Fehler, 0 unverbundene Elemente |
| `kicad-cli sch erc --severity-all` | 0 Fehler, 0 Warnungen |
| `python3 hardware/tests/check_netlist.py` | Exit 0 |
| `python3 hardware/tests/check_kicad.py` | Exit 0, inklusive `check_pcb_connectivity` |
| `python3 hardware/tests/check_fab_release.py` | Exit 0 |
| `analyze_pcb.py --full --stage pre_fab` | keine kritischen Befunde |
| `analyze_emc.py` | Skew in den Grenzen, keine Lücke in der Referenzfläche unter einem Paar, Entkopplungsabstände beanstandungsfrei |
| `analyze_thermal.py` | `U4` und `U6` mit Reserve |
| `fab_release_gate.py --strict` | bestanden |

- [ ] **Step 2: Befunde abarbeiten**

Jeden Befund beheben oder mit Begründung als akzeptiert in `hardware/review/2026-10-31-routed/accepted-findings.md` dokumentieren. Regeln werden nicht aufgeweicht, um einen Befund zum Verschwinden zu bringen. Erfordert eine Behebung eine Geometrieänderung, läuft sie über `route_pcb.py`, nicht über `gen_pcb.py`.

- [ ] **Step 3: Gegen die Basis vergleichen**

Die Kennzahlentabelle aus Task 2 neben die neue stellen und die Unterschiede in `hardware/review/2026-10-31-routed/README.md` festhalten.

- [ ] **Step 4: Prüfungen in `run_all.sh` aufnehmen**

`check_netlist.py`, `check_kicad.py` und `check_fab_release.py` in `hardware/tests/run_all.sh` eintragen, damit sie bei jedem Durchlauf mitlaufen.

- [ ] **Step 5: Commit**

```bash
git add hardware/review/2026-10-31-routed hardware/tests/run_all.sh
git commit -m "Verify the routed board across KiCad, the repo checks and kicad-happy"
```

---

## Task 11: Fertigungsdaten für PCBWay

**Files:**
- Create: `hardware/fab/gerber/`, `hardware/fab/raccoon-tap-cpl.csv`, `hardware/fab/ORDERING.md`
- Modify: `hardware/tests/check_fab_release.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `hardware/fab/stackup-note.md` aus Task 7, die BOM aus Task 6.
- Produces: den vollständigen Satz zum Hochladen bei PCBWay.

- [ ] **Step 1: Den fehlschlagenden Test für Review Focus 4 schreiben**

```python
def test_gerbers_are_newer_than_the_pcb_and_drc_was_clean():
    assert check_gerber_freshness() == []
```

Die Prüfung beanstandet, wenn eine Gerber-Datei älter ist als `raccoon-tap.kicad_pcb` oder wenn neben dem Satz kein DRC-Bericht mit 0 Fehlern liegt.

- [ ] **Step 2: Test laufen lassen und Fehlschlag bestätigen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: FAIL — es gibt keine Gerber.

- [ ] **Step 3: Gerber und Bohrdatei exportieren**

```bash
kicad-cli pcb export gerbers --output hardware/fab/gerber hardware/kicad/raccoon-tap.kicad_pcb
kicad-cli pcb export drill --output hardware/fab/gerber hardware/kicad/raccoon-tap.kicad_pcb
```

Den DRC-Bericht aus Task 10 neben den Satz legen, damit der Test ihn findet.

- [ ] **Step 4: CPL für die Teilbestückung**

`hardware/fab/raccoon-tap-cpl.csv` mit genau einer Bauteilzeile: `U3`, Position und Rotation aus dem PCB, Lage oben. Die Rotation gegen die Pin-1-Markierung des Footprints prüfen, nicht aus der Platzierungstabelle übernehmen.

- [ ] **Step 5: Bestellanleitung**

`hardware/fab/ORDERING.md`: 4 Lagen, 1,6 mm, 1 oz außen, der in Task 7 gewählte Aufbau mit Impedanzkontrolle, Vias unter dem Thermal-Pad abgedeckt, Teilbestückung genau eines Bauteils, Stückzahl 5, Beschaffungslage von `U3` aus Task 6 Step 8, dazu die BOM zum Selbstlöten und der Hinweis, dass alles außer `U3` von Hand bestückt wird.

- [ ] **Step 6: Archivierung entscheiden**

`.gitignore` schließt `hardware/gerber/*.gbr` und `*.drl` aus. Für `hardware/fab/gerber/` eine Ausnahme eintragen, damit der Freigabestand nachvollziehbar bleibt, oder stattdessen Prüfsummen im Repo ablegen. Die Entscheidung in `ORDERING.md` begründen.

- [ ] **Step 7: Tests laufen lassen**

Run: `python3 hardware/tests/check_fab_release.py -v`
Expected: Exit 0.

- [ ] **Step 8: Commit**

```bash
git add hardware/fab .gitignore hardware/tests/check_fab_release.py
git commit -m "Produce the PCBWay fabrication package"
```

---

## Task 12: Dokumentation nachziehen

**Files:**
- Modify: `hardware/netlist.yaml` (`meta`)
- Modify: `hardware/OPEN_QUESTIONS.md`
- Modify: `hardware/design-guide.md`

- [ ] **Step 1: Zustandsangaben wahrheitsgemäß setzen**

`meta.routed: true` und `meta.erc_clean: true` in `netlist.yaml`. Den Maturity-Banner in `OPEN_QUESTIONS.md` so umschreiben, dass er zwischen dem aufgegebenen `raccoon-hat` und dem freigegebenen `raccoon-tap` unterscheidet.

- [ ] **Step 2: Die umgedrehte Entscheidung festhalten**

Den Routing-Punkt in `OPEN_QUESTIONS.md` auf Spec §6.3 umschreiben: die alte Begründung bleibt stehen und wird als überholt markiert, mit dem neuen Argument daneben. Geschlossene Punkte als geschlossen markieren, jeweils mit Verweis auf das Task, das sie geschlossen hat.

- [ ] **Step 3: Dokumenthygiene**

Titel von `OPEN_QUESTIONS.md` nennt noch „HAT" — korrigieren. Die beiden überholten „ERC wurde nicht ausgeführt"-Vorbehalte entfernen. Die veraltete J3-TODO-Zeile und den C9/DVDD12-Punkt streichen (DVDD12 ist an der -VB kein Pin). `design-guide.md` Zeile 295 listet eine DVDD12-Beschaltung, die der verifizierten §2.1 widerspricht — entfernen. Die verwaiste doppelte Tooling-Tabelle löschen. Den toten Querverweis „see item on load caps" auf `netlist.yaml` zeigen lassen.

- [ ] **Step 4: Offen gebliebene Messpunkte zusammenstellen**

Einen Abschnitt „Am ersten Aufbau zu messen" anlegen: `+1V0`-Strom, `+3V3`-Strom gegen die Annahme aus Task 6, `RSET`-Wert für die -VB-Variante. Je Zeile: wie gemessen wird, welches Testpad dafür vorgesehen ist und was bei Abweichung zu tun ist.

- [ ] **Step 5: Prüfungen ein letztes Mal laufen lassen**

Run: `bash hardware/tests/run_all.sh`
Expected: Exit 0.

- [ ] **Step 6: Commit**

```bash
git add hardware/netlist.yaml hardware/OPEN_QUESTIONS.md hardware/design-guide.md
git commit -m "Bring the hardware documentation in line with the released board"
```

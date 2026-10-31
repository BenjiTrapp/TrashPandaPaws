# Raccoon Tap — Freigabe zur Fertigung bei PCBWay

**Status:** Entwurf zur Freigabe
**Datum:** 2026-10-30
**Betrifft:** `vendor/kicad-happy/` (neu), `.opencode/opencode.json` (neu), `hardware/kicad/raccoon-tap.kicad_pcb`, `hardware/kicad/raccoon-tap.kicad_pro`, `hardware/netlist.yaml`, `hardware/bom.csv`, `hardware/tools/gen_pcb.py`, `hardware/tools/gen_bom.py`, `hardware/tests/check_kicad.py`, `hardware/OPEN_QUESTIONS.md`, `hardware/design-guide.md`, `hardware/gerber/` (neu)

---

## 1. Absicht und Begründung

Das Raccoon-Tap-Board ist der USB-3.0-auf-Gigabit-Ethernet-Tap der Drop-Box: er hängt am blauen USB-3.0-Port des Raspberry Pi 4 und stellt den zweiten Ethernet-Port bereit, den die Inline-Bridge braucht. Ohne dieses Board gibt es keinen Datenpfad, in dem der Sniffer sitzen kann.

Der Entwurf ist weiter als sein eigener Ruf. Der Schaltplan ist vollständig, ERC-sauber (0 Fehler, 0 Warnungen unter KiCad 10.0.6) und sein rekonstruierter Netlist ist Netz für Netz identisch mit `netlist.yaml`. Das PCB ist von KiCads eigener `pcbnew`-API erzeugt, hat einen 4-Layer-Stackup, alle 33 Footprints platziert, alle 29 Netze zugewiesen und besteht die DRC mit **null Fehlern**.

Was fehlt, ist eine einzige, große Sache: **es ist keine einzige Leiterbahn gezogen.** 134 unverbundene Pads, 41 Stitching-Vias, die ins Nichts führen, weil es nichts gibt, womit sie sich verbinden könnten. Dazu kommen eine Handvoll elektrischer Punkte, die in `OPEN_QUESTIONS.md` als „vor der Freigabe zu klären" markiert sind, und eine BOM, bei der 10 von 19 Zeilen keine Teilenummer tragen.

Dieses Dokument beschreibt den Weg von dort zu Fertigungsdaten, die bei PCBWay bestellbar sind.

Zusätzlich wird das Analysewerkzeug [kicad-happy](https://github.com/aklofas/kicad-happy) dauerhaft im Repo verankert. Es ist der Grund, warum dieser Schritt überhaupt verantwortbar ist: es prüft Diff-Paar-Skew, die Durchgängigkeit der Referenzfläche unter Hochgeschwindigkeitspaaren, Lücken in der Massefläche, PDN-Impedanz und Sperrschichttemperaturen — also genau die Fehlerklassen, die ein unrouteter Entwurf noch gar nicht zeigen kann und die nach dem Routen über Erfolg oder Platinenneuauflage entscheiden.

---

## 2. Ziele

1. `hardware/kicad/raccoon-tap.kicad_pcb` ist vollständig geroutet: 0 unverbundene Pads, 0 DRC-Fehler.
2. Die sieben Differenzialpaare (USB 3.0 TX/RX, USB 2.0 D+/D−, vier MDI-Paare) halten die Impedanz- und Längenmatching-Ziele aus `netlist.yaml` §stackup ein, mit der Geometrie aus PCBWays eigenem Impedanzrechner statt mit Platzhaltern.
3. Fertigungsdaten liegen in `hardware/gerber/` und sind bei PCBWay bestellbar: Gerber RS-274X, Bohrdatei, Stackup- und Impedanzvorgabe als Fertigungsnotiz.
4. Die BOM trägt für jede Zeile eine lieferbare Teilenummer und ist zum Selbstlöten mit Lötkolben geeignet.
5. Für U3 (RTL8153B, QFN-40, 0,4 mm Raster) existiert eine CPL-Datei für PCBWays Teilbestückung — dieses eine Bauteil wird bestückt, alles andere lötet der Operator selbst.
6. kicad-happy ist so im Repo verankert, dass ein einfacher `git clone` genügt und die Skills nicht lautlos fehlen können.
7. Jeder in `OPEN_QUESTIONS.md` offene, fertigungsblockierende Punkt ist entweder geschlossen oder mit Begründung als bewusst offen markiert.
8. Die bestehende Prüfkette (`hardware/tests/check_kicad.py`, `check_netlist.py`) läuft grün gegen das geroutete Tap-Board.
9. Das Board ist mechanisch befestigbar und hängt nicht allein am USB-Stecker.
10. Das Board verletzt die USB-Spezifikation nicht und hat ESD-Schutz an jedem Pin, der aus dem Gehäuse herausführt.

## 3. Nicht-Ziele

- **Keine Arbeit am `raccoon-hat`-Board.** `OPEN_QUESTIONS.md` Punkt 0 hat PoE zugunsten des offiziellen Raspberry-Pi-PoE+-HAT fallengelassen, `design-guide.md` §1.1 ist als unbaubar markiert. Die HAT-Dateien bleiben unangetastet als Archiv liegen.
- **Keine Rückkehr zu PoE.** Die Stromversorgung kommt über den USB-Stecker.
- **Kein Wechsel des PHY.** Der RTL8153B bleibt, auch wenn sein Gehäuse der Grund für die Teilbestückung ist.
- **Keine Vollbestückung.** Nur U3 wird bestückt.
- **Keine Änderung der Architektur.** Der Entwurf ist Option A und bleibt es.
- **Keine Vorwegnahme von Messungen.** Punkte, die laut `OPEN_QUESTIONS.md` erst am ersten Aufbau messbar sind (+1V0-Strom, RSET-Wert für die -VB-Variante), werden nicht durch Raten geschlossen, sondern als Messpunkte dokumentiert.

## 4. Anti-Ziele

Dinge, die dieses Vorhaben zum Scheitern bringen würden, auch wenn am Ende Gerber-Dateien vorliegen:

- **Ein grünes DRC-Ergebnis, das nichts bedeutet.** Eine Platine, die nur deshalb sauber ist, weil Regeln aufgeweicht wurden, statt weil das Layout stimmt.
- **Geratene Pin-Nummern.** `OPEN_QUESTIONS.md` 3b sagt für die Versorgungs- und Reglerpins von U3 ausdrücklich „Do not infer them." Eine falsche Pin-Nummer an einem QFN-40 ist keine Nachbesserung, sondern eine neue Platine.
- **Impedanz nach Gefühl.** Platzhalter-Geometrie in den Netzklassen, die nie gegen PCBWays wirklichen Stackup gerechnet wurde.
- **Ein Board, das der Operator nicht löten kann.** Wenn am Ende Bauteile drauf sind, die mit Lötkolben und Flussmittel nicht zu schaffen sind, ist das Ziel verfehlt, egal wie gut das Layout ist.
- **Verlorene Provenance.** Dieses Repo dokumentiert an praktisch jedem Pin, woher der Wert kommt. Routing-Arbeit, die undokumentierte Entscheidungen einschleppt, beschädigt genau das, was den Entwurf überprüfbar macht.
- **Stillschweigend gekippte Altentscheidungen.** Siehe Abschnitt 6.3.

---

## 5. Randbedingungen

| Randbedingung | Wert | Quelle |
|---|---|---|
| Fertiger | PCBWay, MPN-basierte Beschaffung | Entscheidung des Operators |
| Bestückung | Nur U3 (Teilbestückung), Rest von Hand | Entscheidung des Operators |
| Löttechnik des Operators | Lötkolben und Flussmittel, keine Schablone, keine Heißluft | Entscheidung des Operators |
| Lagen | 4, 1,6 mm, 1 oz außen | `netlist.yaml` §stackup |
| Lagenbelegung | F.Cu Signale / In1 massiv GND / In2 Power / B.Cu Signale + GND-Pour | `netlist.yaml` §stackup |
| Impedanzziele | USB 3.0 und USB 2.0 90 Ω diff., MDI 100 Ω diff., Referenz In1 | `netlist.yaml` §stackup |
| Längenmatching | USB 3.0 ≤ 2 mm, MDI ≤ 5 mm | `design-guide.md` §4 |
| Boardmaß | 58 × 36 mm, darf wachsen falls die Impedanzgeometrie es erzwingt | `tools/gen_pcb.py`, Entscheidung in 11.8 |
| Stückzahl | 5 Prototypen als Planungsannahme | Entscheidung in 11.11, Operator hatte keine Zahl |
| Bauteilesatz | darf wachsen; Vorgabe des Operators lautet „es soll am Ende funktionieren" | Entscheidung des Operators |
| Befestigung | bisher keine; Befestigungslöcher sind hinzuzufügen | Entscheidung des Operators |
| KiCad | 10.0.6, `kicad-cli` unter `/opt/homebrew/bin` vorhanden | lokal verifiziert |
| Python für kicad-happy | ≥ 3.10; System ist 3.9.6, `python3.12` via Homebrew vorhanden | lokal verifiziert |
| Python für `gen_pcb.py` | KiCads gebündeltes 3.9 mit `pcbnew`-Bindings | `tools/gen_pcb.py` Docstring |
| SPICE | `ngspice` nicht installiert; SPICE-Prüfungen entfallen oder brauchen eine Installation | lokal verifiziert |

### 5.1 Die harte Randbedingung: U3 ist nicht von Hand lötbar

Der RTL8153B-VB-CG ist ein QFN-40 mit 0,4 mm Raster und einem freiliegenden Thermal-Pad auf der Unterseite, das GND führt. Das Mittelpad liegt unter dem Bauteil und ist mit einem Lötkolben von oben nicht erreichbar.

Ausweichen ist nicht möglich: alle USB-3.0-auf-Gigabit-PHYs sind QFN-Gehäuse (RTL8153, AX88179). Ein Gehäuse mit Beinchen existiert für diese Funktion nicht. Der Rückzug auf USB 2.0 würde ein lötbares Gehäuse bringen, wurde aber in `design-guide.md` bereits verworfen — Olimex hat mit demselben PHY über USB 2.0 nur etwa 320 Mbit/s gemessen, und ein Gigabit-Tap, der bei einem Drittel abriegelt, verfehlt den Zweck des Boards.

Daraus folgt die Teilbestückung bei PCBWay für dieses eine Bauteil, und daraus folgen zwei Layout-Konsequenzen:

1. Das Via-Array unter dem Thermal-Pad bleibt (3 × 3, 0,6/0,3 mm auf 1,1-mm-Raster), muss aber **von der Rückseite mit Lötstopplack abgedeckt (tented) oder verschlossen** werden, damit der Reflow-Prozess bei PCBWay kein Lot durch die Vias wegsaugt.
2. Alle anderen Bauteile müssen von Hand lötbar bleiben. Wo das Layout Platz hergibt, werden Passive von 0402 auf 0603 vergrößert — **ausgenommen** die Quarz-Lastkapazitäten C19/C20 und die Entkopplungskondensatoren direkt an U3, die aus Signalintegritätsgründen klein und nah bleiben.

### 5.2 Die mechanische Randbedingung: das Board hängt derzeit am Stecker

Das Board hat **null Befestigungslöcher**. Es trägt eine Winkel-RJ45-Buchse mit Patchkabel und hängt dabei vollständig am USB-A-Stecker — ein 58-mm-Hebel an einer reibschlüssigen Steckverbindung. Zieht jemand am Netzwerkkabel, überträgt sich das auf den USB-Port des Pi.

Der Operator hat bestätigt, dass es bisher keine Befestigung gibt und Löcher hinzugefügt werden dürfen. Das muss **vor** AP5 geschehen, weil ein nachträgliches Loch ein Re-Routing von allem erzwingt, was darüber läuft.

Entschieden (siehe 11.9): zwei M2,5-Befestigungslöcher in den beiden Ecken, die vom USB-Stecker am weitesten entfernt liegen, mit Sperrfläche und Massefläche-Anbindung, plus Zugentlastung für das RJ45-Kabel. Die Lage richtet sich an den Befestigungspunkten des Pi 4 aus, damit das Board gegen dessen Platine verschraubt oder auf Abstandshalter gesetzt werden kann. Welcher der beiden USB-3.0-Ports belegt wird und ob die Lasche nach oben oder unten zeigt, legt dieselbe Entscheidung fest — beides war offen und ist in 11.10 entschieden.

### 5.3 Das Datenblatt-Gate

Der Operator hat **kein** RTL8153B-VB-CG-Datenblatt, und Realtek veröffentlicht dieses nicht. Damit steht die Aussage aus Abschnitt 4 („Do not infer them") gegen das Ziel, das Board fertig zu machen. Aufgelöst wird das nicht durch Raten und nicht durch sofortigen Abbruch, sondern durch eine Abstufung mit definiertem Haltepunkt.

**Stufe 1 — Datenblatt beschaffen.** Der `datasheets`-Skill zieht PDFs über die Distributor-APIs; `lcsc`, `mouser`, `digikey` und `element14` werden nach dem Teil befragt, weil Distributoren das Dokument häufig selbst hosten, auch wenn der Hersteller es nicht öffentlich stellt. Dazu gezielte Websuche nach der bekannten Revision (rev 1.4, Track ID JATR-8275-15).

**Stufe 2 — zwei unabhängige Quellen.** Wenn kein Datenblatt auftaucht: die Pin-Tabelle aus `design-guide.md` §2.1 gegen eine davon **unabhängige** zweite Quelle stellen — ein veröffentlichtes Design, das exakt den RTL8153B-VB-CG im QFN-40 verwendet, oder eine Pinout-Zeichnung eines Distributors. Olimex taugt dafür ausdrücklich nicht: dort sitzt der RTL8153**VC** im QFN-48, und `netlist.yaml` hält bereits fest, dass die Pin-Nummern nicht übertragbar sind. Stimmen zwei unabhängige Quellen überein, gilt der Pinout als belegt, und der Widerspruch zwischen §2.1 und `OPEN_QUESTIONS.md` 3b wird mit dieser Begründung zugunsten von §2.1 geschlossen.

**Stufe 3 — Halt.** Lässt sich der Pinout auf keinem dieser Wege belegen, endet das Vorhaben nach AP1. Es wird kein Routing begonnen, keine BOM bestellt und keine Fertigungsdatei erzeugt. Übergeben wird dann: der kicad-happy-Basisbericht, die geschlossenen Nebenpunkte und eine Liste exakt der Pins, deren Nummer fehlt. Eine Platine mit einer geratenen Versorgungspin-Nummer an einem QFN-40 ist Ausschuss, und Ausschuss ist teurer als Warten.

Diese Stufen laufen als Erstes, vor allem anderen in AP2. Drei weitere offene Punkte hängen an derselben Quelle: die LED-Stromrichtung ([RTL-DS] 6.2), der EECS-Pin und die veraltete DVDD12-Angabe.

---

## 6. Betrachtete Ansätze

### 6.1 Verankerung von kicad-happy

Gemessen: 6,9 MB gesamt, 4,7 MB `skills/`, 225 Dateien, 11 Skills, reines Python ohne Pflicht-Dependencies, Tag `v2`, Commit `2fd9aa0`.

| Ansatz | Vorteil | Nachteil |
|---|---|---|
| Git-Submodul unter `vendor/kicad-happy`, auf `v2` gepinnt | Saubere Provenance, Upgrade ist ein Pointer-Bump, fremder Code bleibt fremd | Wer ohne `--recurse-submodules` klont, bekommt ein leeres Verzeichnis — die Skills fehlen dann **lautlos** |
| **Vendored per `git subtree --squash`** *(gewählt)* | Funktioniert bei jedem einfachen Clone, kann nicht lautlos fehlen, Upstream-Commit wird in der Subtree-Commit-Message festgehalten | 4,7 MB fremder MIT-Code im Repo, Upgrades sind ein Merge statt eines Bumps |
| Nur Zeiger: Konfiguration committen, Checkout außerhalb | Nichts Fremdes im Repo | „Verankert" wäre dann ein Versprechen, keine Tatsache |

**Gewählt: Vendoring.** Begründung: bei einem Prüfwerkzeug ist „fehlt unbemerkt" der schlechteste Fehlermodus. Ein Review, das stillschweigend nicht stattgefunden hat, ist schlimmer als eines, das hart scheitert. 4,7 MB stdlib-Python sind dafür ein billiger Preis.

### 6.2 Wie die Designarbeit organisiert ist

Das Repo behandelt `netlist.yaml` als einzige Quelle der Wahrheit; `gen_schematic.py`, `gen_pcb.py` und `gen_bom.py` erzeugen daraus Schaltplan, Platine und BOM. Routing passt in dieses Modell schlecht.

| Ansatz | Vorteil | Nachteil |
|---|---|---|
| Generator-first: Routing-Stufe in `gen_pcb.py` | Bleibt vollständig in der bestehenden Disziplin, alles reproduzierbar erzeugt | Bedeutet, einen diff-paar-fähigen Router mit Längenmatching in Python zu schreiben: viel Aufwand für ausgerechnet auf den Netzen das schwächste Ergebnis, auf die es am meisten ankommt |
| **PCB wird gepflegtes Artefakt** *(gewählt)* | Geometrie wird gezielt gesetzt statt generisch erzeugt; die Garantie bleibt dort, wo sie zählt | Das PCB ist ab dann nicht mehr aus `netlist.yaml` reproduzierbar; Konnektivität muss stattdessen laufend gegengeprüft werden |
| Kritische Paare an den Operator abgeben | Beste Geometrie | Das Board ist erst fab-fähig, wenn der Operator Zeit hatte — widerspricht dem Ziel |

**Gewählt: PCB als gepflegtes Artefakt.** Konkret:

- `netlist.yaml` bleibt maßgeblich für **Konnektivität**. Schaltplan, BOM und Netzzuweisung werden weiter generiert.
- Die **Leitungsgeometrie** lebt ab jetzt in `raccoon-tap.kicad_pcb` und wird nicht mehr neu erzeugt. `gen_pcb.py` bekommt einen Warnhinweis, dass ein erneuter Lauf das Routing vernichtet.
- Als Ersatz für die verlorene Reproduzierbarkeit wird `check_kicad.py` so erweitert, dass es die Konnektivität des **gerouteten** Boards gegen `netlist.yaml` verifiziert. Damit kann ein Routing-Fehler, der ein Netz falsch verbindet, nicht unentdeckt bleiben.

### 6.3 Die umgedrehte Entscheidung: Routing wird programmatisch gesetzt

Hier wird eine im Repo schriftlich getroffene Entscheidung revidiert. Das wird hier festgehalten, damit die Umkehr nachvollziehbar bleibt.

**Die alte Entscheidung.** `tools/gen_pcb.py` sagt in seinem Docstring:

> What this deliberately does NOT do: route anything. The seven differential pairs need KiCad's interactive differential-pair router with a human deciding geometry and length matching. An autorouted result would be an unverifiable artefact — see OPEN_QUESTIONS.md.

`OPEN_QUESTIONS.md` begründet das beim Punkt „Routing" zusätzlich damit, dass FreeRouting bei 4-Layer-Boards die Innenlagen ignoriert.

**Warum sie umgedreht wird.** Der damalige Einwand hatte zwei Teile. Der erste — FreeRouting ignoriert Innenlagen — betrifft einen bestimmten Autorouter und nicht gezielt gesetzte Geometrie; er bleibt gültig und wird respektiert, indem FreeRouting nicht eingesetzt wird. Der zweite und tragende Teil war „unverifiable artefact": es gab kein Werkzeug, mit dem man einem maschinell erzeugten Layout ansehen konnte, ob es gut ist.

Dieses Werkzeug gibt es jetzt. kicad-happy prüft Diff-Paar-Skew gegen Zeitgrenzen, die Durchgängigkeit der Referenzfläche unter jedem Hochgeschwindigkeitspaar, Lücken und Schlitze in der Massefläche, Abstände von Entkopplungskondensatoren zu ihren Versorgungspins, PDN-Impedanz über den Power-Tree und Sperrschichttemperaturen. Das Artefakt ist damit nicht mehr unverifizierbar, und der tragende Grund für das Verbot entfällt.

**Was dadurch nicht besser wird.** Die sieben Paare werden geometrisch schlechter aussehen als von einer geübten Hand im interaktiven Router gezogen. Das ist der bewusst eingegangene Preis dafür, dass das Board ohne Operator-Einsatz fertigungsreif wird. Der Operator sieht das Ergebnis vor der Bestellung in KiCad an.

**Festzuhalten im Repo:** der Docstring in `gen_pcb.py` und der Routing-Punkt in `OPEN_QUESTIONS.md` werden auf diese Entscheidung umgeschrieben, mit Verweis auf dieses Dokument. Die alte Begründung wird nicht gelöscht, sondern als überholt markiert.

---

## 7. Ausgangszustand, verifiziert

Alles in diesem Abschnitt wurde am 2026-10-30 lokal gegen die Dateien geprüft, nicht aus der Dokumentation übernommen.

### 7.1 Schaltplan — fertig

- `kicad-cli sch erc --severity-all`: 0 Fehler, 0 Warnungen.
- Rekonstruierter Netlist gegen `netlist.yaml`: 28 von 28 Netzen identisch.
- 131 von 131 Drahtenden liegen auf einem Pin, 131 von 131 Labels sind an einem Draht.

### 7.2 PCB — platziert, nicht geroutet

| Messung | Wert |
|---|---|
| Footprints | 33 |
| Leiterbahnsegmente | **0** |
| Vias | 41 (GND-Stitching und Thermal-Array) |
| Zonen | 4 |
| Lagen | F.Cu, In1.Cu („GND"), In2.Cu („Power"), B.Cu |
| `kicad-cli pcb drc` | 43 Verstöße: 41 × `via_dangling`, 2 × `silk_over_copper` — **alle Warnungen, 0 Fehler** |
| Unverbundene Elemente | 134 |

Die 41 dangling Vias sind kein Defekt, sondern die Folge des fehlenden Routings: Stitching-Vias ohne eine Bahn, die sie anbindet.

### 7.3 Korrektur einer eigenen Fehlannahme

Im Gespräch wurde zunächst festgestellt, `raccoon-tap.kicad_pcb` habe keine Netztabelle und sei deshalb defekt, weil die Pads `(net "GND")` statt `(net 1 "GND")` tragen. **Das war falsch.** `gen_pcb.py` schreibt die Datei über KiCads eigene `pcbnew`-API; die namensbasierte Form ist das, was KiCad 10 selbst erzeugt. Das alte HAT-Board hat eine Integer-Tabelle, weil es von `fix_pcb_nets.py` im KiCad-9-Format geschrieben wurde. Es handelt sich um einen Formatwechsel, nicht um einen Defekt.

Daraus folgt aber eine echte Aufgabe: `hardware/tests/check_kicad.py` erzwingt noch die alte Regel („a net table must exist, every reference must use an integer id") und prüft überdies `raccoon-hat.kicad_pcb` statt des Tap-Boards. Gegen das Tap-Board gerichtet würde es heute fälschlich scheitern. Die Prüfung muss auf das KiCad-10-Format und auf das richtige Board umgestellt werden.

### 7.4 Fertigungsblockierende offene Punkte

Aus `OPEN_QUESTIONS.md` und `netlist.yaml`, nach Schwere sortiert:

| ID | Punkt | Warum es blockiert |
|---|---|---|
| 3b | Versorgungs- und Reglerpins von U3 nicht bestätigt (`AVDD10`, `AVDD33`, `DVDD10`, `DVDD33`, `VDD5`, `REGOUT`, `DVDD10_UPS`, `RSET`, `GND`) — die Pin-Belegungsabbildung ließ sich nicht aus dem PDF extrahieren, ausdrücklich „Do not infer them" | Falsche Pin-Nummer am QFN-40 = neue Platine. **Höchste Priorität**, Vorgehen in 5.3. Zu beachten: `design-guide.md` §2.1 listet diese Pins bereits mit Nummern, ohne dass der Warnhinweis zurückgezogen wurde — es ist zu klären, ob die Abbildung später gelesen wurde oder ob §2.1 genau die verbotene Ableitung enthält |
| **neu** | **21 µF Bulk direkt an VBUS** (C1 10 µF + C3 10 µF + C5 1 µF + 2 × 100 nF) gegen 10 µF Grenze der USB-Spezifikation, ohne Soft-Start und ohne Load-Switch | Einschaltstromstoß kann den Port einbrechen lassen oder die Strombegrenzung des VL805 im Pi auslösen — das Board würde beim Einstecken den Host stören |
| **neu** | **Kein ESD-Schutz auf D+/D−** und keiner auf den SuperSpeed-Paaren, auf einem Board, dessen Zweck das Einstecken in einen fremden Host ist | Ein ESD-Ereignis am Stecker geht direkt in den PHY und in den Pi |
| `design_notes.usb3_crossover` | Host-/Device-Benennung von SSTX/SSRX am USB-A-Stecker: „Verify against the connector's own datasheet before layout release — a swap here costs a board spin" | Vertauschte Paare = neue Platine |
| 3g / Netzklassen | Diff-Paar-Breite und -Abstand sind Platzhalter, keine gerechnete Geometrie | Ohne PCBWays wirklichen Stackup ist die Impedanz unbekannt |
| In2-Plane | In2 ist als eine durchgehende +3V3-Fläche erzeugt und muss in +5V-, +3V3- und +1V0-Inseln aufgeteilt werden | Sonst sind zwei der drei Rails nicht versorgt |
| J2-Orientierung | Zu prüfen, dass die RJ45-Öffnung zur Platinenkante zeigt | Mechanischer Fehler, nach der Fertigung nicht korrigierbar |
| `SHIELD`-Anbindung | Einpunkt-Masse direkt oder 1 nF ∥ 1 MΩ — „leaving the shield genuinely floating would make it an antenna" | Muss vor der Layout-Freigabe entschieden sein |
| Y1 | Kein Quarz ausgewählt; Footprint ist Platzhalter, C19/C20 (39 pF) sind `TBD` bis der Quarz steht und müssen aus dessen CL berechnet werden | Ohne Teil kein Footprint und keine BOM-Zeile |
| `design_notes.led_polarity` | Annahme, die LED-Pins des RTL8153B senken Strom; [RTL-DS] 6.2 „must be read to confirm before release" | Falsche Richtung = LEDs tot, Widerstände müssten auf die Kathodenseite |
| BOM | 10 von 19 Zeilen ohne Teilenummer | PCBWay beschafft MPN-basiert |
| Footprint U3 | Zu bestätigen, dass `Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` in der installierten KiCad-Bibliothek auflöst | Sonst scheitert der Plot |

Nicht blockierend, aber zu dokumentieren: `RSET` = 2,49 kΩ ist aus Olimex' **VC**-Variante übernommen und für die **-VB** unbestätigt (Nachbesserung, keine Neuauflage — ein 0402 zum Tauschen vorsehen); der +1V0-Strom ist in [RTL-DS] nicht spezifiziert und am ersten Aufbau zu messen; für den R5/R6-Teiler an U6 ist kein Feed-Forward-Kondensator vorgesehen, was eine bewusste Entscheidung verdient (ein DNP-Pad kostet nichts).

---

## 8. Arbeitspakete

### AP0 — kicad-happy verankern

`git subtree add --prefix vendor/kicad-happy --squash` auf Tag `v2`. `.opencode/opencode.json` mit `{"skills": {"paths": ["./vendor/kicad-happy/skills"]}}`. Prüfen, dass `.gitignore` nichts davon schluckt. Kurze Notiz in `hardware/OPEN_QUESTIONS.md` §Tooling, womit analysiert wird und wie man es aktualisiert. Die Skripte unter `python3.12` lauffähig bestätigen, da das System-`python3` 3.9.6 ist.

### AP1 — Basis-Review

kicad-happy gegen den Ist-Zustand laufen lassen: Schaltplananalyse, PCB-Analyse, Cross-Analyse, EMC, Thermik. Ergebnis als Bericht unter `hardware/review/` committen. Das ist die Vergleichsbasis: alles später Gefundene lässt sich dagegen messen, und der Bericht wird zeigen, welche der oben gelisteten Punkte das Werkzeug selbständig findet und welche es übersieht.

### AP2 — Elektrisch offene Punkte schließen

Reihenfolge nach Schwere. Der Datenblatt-Skill lädt die PDFs und extrahiert Pinouts strukturiert — genau das Problem, an dem die Handarbeit in 3b gescheitert ist.

0. **Datenblatt-Gate durchlaufen** (Abschnitt 5.3). Stufe 1 Beschaffung, Stufe 2 zwei unabhängige Quellen, Stufe 3 Halt. Dieser Schritt steht vor allen anderen; ohne belegten Pinout wird nichts weiter gebaut.
1. **U3-Pinout vollständig verifizieren.** Pin-Belegung gegen `netlist.yaml` **und** gegen `design-guide.md` §2.1 abgleichen. Den Widerspruch aus 3b auflösen und das Ergebnis mit Quellenangabe festhalten.
2. **USB-3.0-Crossover** gegen das Würth-692112030100-Datenblatt prüfen.
3. **LED-Richtung** aus [RTL-DS] 6.2 bestätigen.
4. **Quarz auswählen** (25 MHz, Lastkapazität bekannt), C19/C20 daraus berechnen, Footprint festlegen.
5. **`SHIELD`-Strategie entscheiden** und in `netlist.yaml` `design_notes.shield_tie` festschreiben.
6. **VBUS-Einschaltverhalten in Ordnung bringen.** Bulk-Kapazität auf das von der USB-Spezifikation erlaubte Maß bringen und einen Load-Switch mit Soft-Start oder eine gleichwertige Einschaltstrombegrenzung aufnehmen. Der Operator hat den Bauteilesatz hierfür ausdrücklich geöffnet.
7. **ESD-Schutz aufnehmen.** Auf D+/D− ein Standard-Array; auf den SuperSpeed-Paaren nur Bauteile mit ausreichend geringer Kapazität, damit die 90-Ω-Strecke nicht verstimmt wird. Auf den MDI-Paaren ist der Schutz durch die Magnetik und die integrierte Bob-Smith-Terminierung in J2 bereits gegeben.
8. **Messpunkte vorsehen.** Testpads und je eine auftrennbare Serienbrücke in +3V3 und +1V0, damit die bewusst auf den ersten Aufbau verschobenen Strommessungen (Nicht-Ziel 6) überhaupt durchführbar sind. Ohne diese Pads ist die Messung später nicht möglich, und das muss vor dem Einfrieren passieren.
9. **Feed-Forward-Pad an R5/R6** als DNP vorsehen oder begründet weglassen.
10. **U3-Footprint-Auflösung** in der installierten Bibliothek bestätigen.

Alles, was die Konnektivität berührt, geht in `netlist.yaml` und wird über die Generatoren in Schaltplan und BOM gezogen — die Reihenfolge ist wichtig, weil AP6 das PCB ab dann einfriert.

### AP3 — BOM auf Bestellniveau

Für die Zeilen ohne Teilenummer über die Distributor-Skills (Mouser, DigiKey, element14, LCSC) lieferbare Teile suchen. Pro Zeile: Teilenummer, Gehäuse, Preis, Verfügbarkeit, Lebenszyklus. Dabei Gehäuse von 0402 auf 0603 heben, wo das Layout es erlaubt und Signalintegrität es nicht verbietet. Lebenszyklusprüfung über alle Zeilen, damit kein EOL-Teil in die Bestellung gerät. Ergebnis über `gen_bom.py` aus `netlist.yaml` erzeugen, nicht in `bom.csv` hineinschreiben.

**Zusätzlich und eigens hervorgehoben: die Verfügbarkeit von U3 selbst prüfen.** Der RTL8153B-VB-CG trägt bereits eine Teilenummer und fällt deshalb aus der Lückensuche heraus, ist aber das einzige Teil, das Realtek über eigene Kanäle vertreibt. Zu klären ist, ob PCBWay es beschaffen kann oder ob es beigestellt werden muss — Letzteres bedeutet Vorlaufzeit, Mindestabnahme und ein Fälschungsrisiko, das bei Netzwerk-PHYs aus Graumarktquellen real ist. Ergebnis und Preis werden dem Operator vorgelegt, bevor irgendetwas bestellt wird.

### AP4 — Impedanzgeometrie von PCBWay

PCBWays 4-Layer-Stackup und Impedanzrechner heranziehen und die wirkliche Breite/Abstand-Geometrie für 90 Ω und 100 Ω auf ihren tatsächlichen Kern- und Prepreg-Dicken bestimmen. Die Netzklassen `USB3` und `MDI` in `raccoon-tap.kicad_pro` von Platzhaltern auf diese Werte setzen. Die Stackup-Vorgabe als Fertigungsnotiz formulieren, die der Bestellung beiliegt. Dieses Arbeitspaket muss **vor** AP6 fertig sein, weil es die Geometrie festlegt, mit der geroutet wird.

Die derzeitigen Platzhalter sind schmal. Fällt die gerechnete Geometrie deutlich breiter aus, wird es auf 58 × 36 mm mit sieben Paaren eng, und zwar genau dort, wo auch das 0,4-mm-Raster von U3 Platz braucht. Die Rangfolge der Auswege ist vorab festgelegt (siehe 11.8): zuerst das Board vergrößern, dann die Bahnführung umlegen; Dicke, Kupferstärke und Impedanzkontrolle selbst bleiben unangetastet, weil sie den Preis und die Fertigbarkeit bestimmen. Reicht das nicht, ist das ein Haltepunkt mit Rückfrage, kein stilles Aufweichen der Impedanzziele.

### AP5 — Platzierung überarbeiten

Die Platzierung ist generatorerzeugt nach Signalfluss und courtyard-sauber, aber in einem Punkt gegen das wichtigste Ziel gerichtet: U3 steht auf Rotation 0, womit seine MDI-Pins 1–10 auf der **linken** Kante liegen und zum USB-Stecker zeigen, während J2 21 mm weiter **rechts** sitzt. So müssten die vier 100-Ω-MDI-Paare um das Gehäuse herumlaufen und die SuperSpeed-Ausführung kreuzen. Das ist gegen Ziel 2 nicht haltbar, deshalb wird **U3 gedreht** und der Quarzblock samt Entkopplungsring mit ihm bewegt (Entscheidung 11.7). Das ist eine echte Neuplatzierung, keine Nacharbeit, und sie macht die committete DRC-Basis aus AP1 ungültig — die Basis wird danach neu erhoben.

Alle Platzierungsänderungen gehen in die `PLACEMENT`-Tabelle von `gen_pcb.py` und werden von dort erzeugt, **nicht** von Hand im PCB verschoben. Das Einfrieren beginnt erst mit AP6.

Weiter zu tun: Befestigungslöcher und Zugentlastung aus 5.2 einbringen; Entkopplungskondensatoren an ihre Versorgungspins heranziehen (kicad-happy misst den Abstand und beanstandet ihn); C21 nah an die PHY-seitigen Mittelanzapfungen von J2; J2-Orientierung so festlegen, dass die RJ45-Öffnung zur Platinenkante zeigt; den Buck-Hot-Loop um U6 klein halten und den R5/R6-Teiler vom LX-Schaltknoten wegziehen; U4 so platzieren und mit Kupferfläche versehen, dass die Verlustleistung aus 11.12 abgeführt wird; In2 in +5V-, +3V3- und +1V0-Inseln aufteilen; die Vias unter U3s Thermal-Pad von der Rückseite abdecken.

### AP6 — Routen

Ab hier ist das PCB ein gepflegtes Artefakt. `gen_pcb.py` darf nicht mehr darüber laufen.

Reihenfolge nach absteigender Empfindlichkeit, damit die kritischen Netze den Platz bekommen:

1. **USB 3.0 SuperSpeed** (TX- und RX-Paar) — auf F.Cu, durchgehend über der massiven In1-Fläche, kurz, Längendifferenz innerhalb des Paares ≤ 2 mm, keine Vias wenn vermeidbar, kein Lagenwechsel unter dem Paar.
2. **MDI 0–3** — vier Paare von U3 zu J2, 100 Ω, Längendifferenz ≤ 5 mm, ebenfalls über ununterbrochener Referenzfläche. Die Isolationsgrenze an J2 respektieren: der kabelseitige SHIELD-Pour bleibt vom Signal-GND getrennt und wird nur am vorgesehenen Einzelpunkt verbunden.
3. **USB 2.0 D+/D−** — 90 Ω, dasselbe Regime, geringere Schärfe.
4. **Buck-Hot-Loop** um U6 — IN → LX → L2 → COUT → GND klein und auf F.Cu, breite Bahnen, Rückstrom kurz.
5. **Versorgungen** — Breite nach Strom, über die In2-Inseln, Entkopplung mit kurzen Stichen an die Pins.
6. **Niedergeschwindigkeitsnetze** — LEDs, RSET und was übrig ist.
7. **U3-Thermal-Pad** an In1 stitchen und die Perimeter-Stitching-Vias anbinden, damit die 41 dangling Vias verschwinden.

Eiserne Regeln aus `netlist.yaml` §stackup.rules, die bei jedem Schritt gelten: die In1-Massefläche wird unter keinem Differenzialpaar unterbrochen; jedes Paar behält über seine gesamte Länge eine durchgehende Referenz.

### AP7 — Verifikation

Nicht eine Prüfung, sondern eine Kette, und keine Erfolgsmeldung ohne Ausgabe:

| Prüfung | Kriterium |
|---|---|
| `kicad-cli pcb drc --severity-all` | 0 Fehler, 0 unverbundene Elemente |
| `kicad-cli sch erc --severity-all` | 0 Fehler, 0 Warnungen (muss nach AP2 noch gelten) |
| `check_netlist.py` | grün |
| `check_kicad.py` *(auf KiCad-10-Format und Tap-Board umgestellt)* | grün, inklusive Konnektivität des gerouteten Boards gegen `netlist.yaml` |
| kicad-happy PCB-Analyse | keine kritischen Befunde |
| kicad-happy EMC | Diff-Paar-Skew innerhalb der Grenzen, keine Lücke in der Referenzfläche unter einem Paar, Entkopplungsabstände beanstandungsfrei |
| kicad-happy Thermik | Sperrschichttemperaturen von U4 und U6 mit Reserve |
| kicad-happy Fab-Release-Gate | bestanden, offene Warnungen begründet |

Befunde aus den kicad-happy-Läufen werden nicht wegkonfiguriert, sondern behoben oder mit Begründung als akzeptiert dokumentiert.

### AP8 — Fertigungsdaten für PCBWay

Gerber RS-274X und Bohrdatei nach `hardware/gerber/` (das `.gitignore` schließt `*.gbr` und `*.drl` aus — zu entscheiden, ob für eine Freigabe eine Ausnahme sinnvoll ist, siehe Abschnitt 10). Dazu: Stackup- und Impedanzvorgabe als Fertigungsnotiz, die BOM zum Selbstlöten, eine CPL-Datei mit U3s Position und Rotation für die Teilbestückung, und eine kurze Bestellanleitung, die festhält, was bei PCBWay anzugeben ist — Lagen, Dicke, Kupfer, Impedanzkontrolle, Teilbestückung genau eines Bauteils, Vias unter dem Thermal-Pad abgedeckt.

### AP9 — Dokumentation nachziehen

`netlist.yaml` `meta.routed` und `meta.erc_clean` auf den wahren Stand. Den Routing-Punkt in `OPEN_QUESTIONS.md` und den Docstring in `gen_pcb.py` auf die Entscheidung aus 6.3 umschreiben. Geschlossene Punkte als geschlossen markieren. Die Dokumenthygiene aus der Analyse mit erledigen: der Titel von `OPEN_QUESTIONS.md` nennt noch „HAT"; der Maturity-Banner und zwei „ERC wurde nicht ausgeführt"-Vorbehalte sind überholt; die J3-TODO-Zeile und der C9/DVDD12-Punkt sind veraltet (DVDD12 ist an der -VB kein Pin); `design-guide.md` Zeile 295 listet noch eine DVDD12-Beschaltung, die der verifizierten §2.1 widerspricht; eine verwaiste doppelte Tooling-Tabelle ist zu löschen.

---

## 9. Was dem Umsetzenden überlassen bleibt

- Die konkrete Bahnführung innerhalb der Regeln aus AP6. Vorgegeben sind Reihenfolge, Lagen, Impedanz, Längenmatching und Referenzflächenregeln, nicht jede Koordinate.
- Welche Passiven von 0402 auf 0603 wachsen. Entscheidungsregel: alles außer C19/C20 und den Entkopplungskondensatoren direkt an U3, soweit der Platz es hergibt.
- Die Form der Berichte unter `hardware/review/`.
- Welche Bauteile unter mehreren gleich geeigneten gewählt werden, solange Lebenszyklus und Verfügbarkeit geprüft sind.
- Ob `ngspice` installiert wird, um die SPICE-gestützten EMC-Prüfungen zu schärfen. Ohne fällt kicad-happy auf analytische Modelle zurück; das Board kommt auch so durch.

## 10. Risiken

| Risiko | Auswirkung | Umgang |
|---|---|---|
| U3s Versorgungspins lassen sich auf keinem Weg belegen | Projektende nach AP1 — raten ist ausgeschlossen (Anti-Ziel) | Abgestuftes Datenblatt-Gate in 5.3, durchlaufen als Erstes. Stufe 3 ist ein geordneter Halt mit Übergabe, kein Scheitern mitten im Layout |
| U3 ist nicht beschaffbar oder nur aus Graumarktquellen | Ein perfekt geroutetes Board ohne PHY | AP3 prüft die Verfügbarkeit ausdrücklich mit und legt Preis und Quelle vor der Bestellung vor |
| Programmatisch gesetzte Diff-Paare erfüllen Skew oder Referenzdurchgängigkeit nicht | Nacharbeit, im schlechtesten Fall doch interaktives Routen | kicad-happy EMC nach jedem Paar, nicht erst am Ende. Obergrenze: drei Iterationen pro Paar, danach Halt und Übergabe des platzierten Boards (11.13) |
| PCBWays Impedanzgeometrie passt nicht auf 58 × 36 mm | Boardfläche muss wachsen oder die Führung sich ändern | AP4 vor AP6; festgelegte Rangfolge der Auswege in 11.8, Haltepunkt mit Rückfrage statt stiller Aufweichung |
| Teilbestückung eines einzelnen QFN ist bei PCBWay unverhältnismäßig teuer | Kostenentscheidung des Operators | Preis in AP8 bei 5 Stück feststellen und vorlegen, bevor bestellt wird |
| Die Neuplatzierung in AP5 bringt neue DRC-Verstöße | Die saubere Basis aus AP1 ist verloren | Basis nach AP5 neu erheben; die Erfahrung aus `OPEN_QUESTIONS.md` (DRC stieg schon einmal von 263 auf 269, weil eine Korrektur neue Kollisionen schuf) zeigt, dass nach jeder Platzierungsänderung neu gemessen werden muss |
| `.gitignore` schließt Gerber aus, die Freigabe soll aber nachvollziehbar sein | Fertigungsdaten der Freigabe sind nicht archiviert | In AP8 entscheiden: Ausnahme für einen Freigabestand oder eine Prüfsumme im Repo |
| Das geroutete PCB ist nicht mehr aus `netlist.yaml` reproduzierbar | Ein Routing-Fehler könnte ein Netz still falsch verbinden | Erweiterte `check_kicad.py` prüft Konnektivität gegen `netlist.yaml`; Warnhinweis in `gen_pcb.py` |
| kicad-happy ist ein fremdes Werkzeug mit eigenen Fehlern | Falsche Befunde oder übersehene Fehler | Es ersetzt KiCads ERC/DRC nicht, es ergänzt sie. Beide laufen |

## 11. Entscheidungen, die ich getroffen habe

Festgehalten, damit sie beim Lesen überprüfbar sind und nicht als abgestimmt durchgehen:

1. **Vendoring statt Submodul** für kicad-happy (6.1). Begründung: lautloses Fehlen ist der schlechteste Fehlermodus.
2. **Vias unter U3s Thermal-Pad werden abgedeckt**, statt das Via-Array zu verkleinern. Begründung: die thermische Anbindung bleibt erhalten, und der Reflow-Prozess ist PCBWays Problem, nicht das des Operators.
3. **Passive wachsen auf 0603**, wo Platz und Signalintegrität es zulassen. Begründung: folgt direkt aus „Lötkolben und Flussmittel".
4. **Routing-Reihenfolge nach absteigender Empfindlichkeit** (AP6). Begründung: die kritischen Netze bekommen den Platz, bevor ihn unkritische verbrauchen.
5. **`raccoon-hat` wird nicht angefasst.** Begründung: `OPEN_QUESTIONS.md` Punkt 0 hat das Board bereits aufgegeben.
6. **Der +1V0-Strom und der RSET-Wert werden nicht geschlossen**, sondern als Messpunkte für den ersten Aufbau dokumentiert — jetzt mit Testpads und auftrennbaren Serienbrücken, damit die Messung technisch möglich ist (AP2.8). Begründung: beides sind Nachbesserungen, keine Platinenneuauflagen, und Messen schlägt Raten.
7. **U3 wird gedreht** (AP5). Begründung: in der aktuellen Lage zeigen die MDI-Pins weg von J2, was die vier 100-Ω-Paare um das Gehäuse und über die SuperSpeed-Ausführung zwingen würde. Ziel 2 wiegt schwerer als die Erhaltung der bestehenden DRC-Basis.
8. **Rangfolge, wenn die Impedanzgeometrie nicht passt** (AP4): erst das Board vergrößern, dann die Führung umlegen. Dicke, Kupferstärke und die Impedanzkontrolle selbst bleiben unangetastet, weil sie Preis und Fertigbarkeit bestimmen. Danach Halt mit Rückfrage. Begründung: der Operator hat das Boardmaß freigegeben, nicht den Fertigungsprozess.
9. **Zwei M2,5-Befestigungslöcher** in den Ecken fern des USB-Steckers, plus Zugentlastung für das RJ45-Kabel (5.2). Begründung: der Operator hat gesagt, es gibt bisher keine Befestigung und ich darf welche anbringen. Ein Board, das nur am Stecker hängt, überträgt jeden Zug am Patchkabel auf den USB-Port des Pi.
10. **Unterer USB-3.0-Port, Lasche nach unten**, Löcher auf die Befestigungspunkte des Pi 4 ausgerichtet. Begründung: war offen, der Operator hatte keine Vorgabe, und irgendeine Festlegung muss vor AP5 stehen. Leicht zu ändern, solange es vor dem Einfrieren geschieht.
11. **Planungsannahme 5 Prototypen.** Begründung: der Operator hatte keine Zahl. Die Zahl beeinflusst nur die Kostenvorlage in AP8, nicht das Layout, und wird vor der Bestellung bestätigt.
12. **Auslegungsstrom für +3V3 wird festgelegt**, statt die Frage offen zu lassen. Begründung: Nicht-Ziel 6 verbietet, eine *offene Frage durch Raten zu schließen* — es verbietet nicht, für die Kupferdimensionierung eine dokumentierte konservative Annahme zu treffen. Ohne eine Zahl sind die In2-Inseln und die Thermikprüfung in AP7 bedeutungslos. Die Zahl wird mit dem Datenblatt in AP2 belegt und bleibt am ersten Aufbau zu messen. Zeigt die Rechnung, dass der AP2112K im SOT-23-5 thermisch nicht reicht, darf U4 getauscht werden — vor dem Einfrieren.
13. **Obergrenze von drei EMC-Iterationen pro Differenzialpaar.** Begründung: die Umkehr in 6.3 stand auf der Annahme, dass Operator-Zeit nicht verfügbar ist. Ohne Obergrenze wird daraus eine offene Schleife. Nach drei erfolglosen Durchgängen an einem Paar wird das platzierte Board mit Routing-Briefing übergeben, statt weiter zu probieren.
14. **Bulk-Kapazität und ESD werden aufgenommen** (AP2.6, AP2.7). Begründung: der Operator hat den Bauteilesatz geöffnet mit „es soll am Ende funktionieren". Ein Board, das beim Einstecken den Host-Port stört oder den PHY bei der ersten statischen Entladung verliert, funktioniert nicht.
15. **Dokumenthygiene läuft mit** (AP9), statt in einem eigenen Vorhaben. Begründung: die widersprüchlichen Altangaben haben in diesem Gespräch bereits zu einer Fehlannahme geführt (7.3); sie kosten beim nächsten Mal wieder Zeit.

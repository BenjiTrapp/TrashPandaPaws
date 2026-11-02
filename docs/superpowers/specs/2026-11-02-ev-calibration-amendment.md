# Nachtrag: EV-Kalibrierung

**Datum:** 2026-11-02
**Ändert:** `2026-10-30-autonomous-agent-layer-design.md`, §10.5 und §10.8
**Status:** zur Abnahme
**Anlass:** Am fertigen Gate (Task 4) gemessen: im Full Automated lehnt der
EV-Schiedsrichter bei Schwelle 0 **alle elf** Stufe-2-Aktionen ab. Full-Auto
ist damit verhaltensgleich zu `unattended_behavior="skip"`, obwohl §10.7
sagt, das Gate verschwinde nie und nur der Entscheider wechsle.

Die Implementierung ist spec-treu. Die Spec ist an zwei Stellen inkonsistent.

---

## 1 Der Befund

Gemessen, Schwelle 0, keine Detection:

```
remote_exec  75×0.8 − 100×0.6 =   0.0    persist      25×0.9 − 100×0.25 =  −2.5
exploit      25×0.6 − 100×0.3 = −15.0    deauth       30×0.7 − 100×0.4  = −19.0
ntlm_relay   75×0.4 − 100×0.5 = −20.0    iface_change  0×0.9 − 100×0.2  = −20.0
responder    50×0.6 − 100×0.55= −25.0    dev_write     0×0.8 − 100×0.3  = −30.0
lsass_dump   50×0.5 − 100×0.7 = −45.0    log_clear     0×0.8 − 100×0.8  = −80.0
shadow_copy   0×0.8 − 100×0.85= −85.0
```

### 1.1 Zwei Punkteskalen sind vermischt

§10.5s Risikotabelle bepunktet **die Aktion**: `persist` → 0, weil das
Installieren von Persistenz kein Scoring-Ziel ist. §10.8s Tabelle bepunktet
**das Ergebnis**: `privilege_escalation` +150, `rce_achieved` +200.

`punkte × P(erfolg)` ist ein Erwartungs*wert*. Der Nutzen-Term muss also sein,
**was die Aktion freischaltet**, nicht ihr eigenes Score-Etikett. §10.8
behauptet, beide Tabellen seien identisch — sie sind es nicht.

### 1.2 Das GUI-Beispiel rechnet mit anderen Zahlen

§15 zeigt `EV: 25×0.60 − 100×0.12 = +3.0 → proceed`. Das ist
`exploit_known_poc` mit P(detect) **0,12**; §10.5 gibt **0,30**. Es ist die
einzige Stelle der Spec, an der eine EV positiv herauskommt — das Beispiel
wurde gegen eine andere Tabelle gerechnet als die, die gilt.

### 1.3 §10.6 setzt voraus, dass Aktionen vorher erlaubt sind

> „nach einer Detection steigt P(detect) um 0.15, was die meisten Stufe-2-
> Aktionen mit Punkten unter 100 automatisch unter die EV-Schwelle drückt"

Das ist nur sinnvoll, wenn sie vorher darüber liegen.

---

## 2 Die Korrektur

Drei Änderungen, zusammen.

### 2.1 Der Nutzen-Term wird der Ergebniswert

§10.5s Tabelle bekommt eine Spalte **„schaltet frei"** und bezieht ihren
Punktwert aus §10.8s Scoring-Tabelle — **unverändert**, die Scoring-Tabelle
ist die CTF-Wertung und bleibt, wie sie ist.

Regel: **nur das unmittelbare Ergebnis**, nicht die Folgekette. Jede
Folgeaktion durchläuft ihre eigene EV-Bewertung; die Kette mitzuzählen würde
jede frühe Aktion künstlich aufwerten.

Für reine Wegbereiter mit Punktwert 0 (`persist`, `iface_change`) tritt der
Wert dessen ein, was sie **ermöglichen oder erhalten**.

### 2.2 Der Risikokoeffizient wird von der Score-Strafe getrennt

Heute steht in beiden Rollen dieselbe Zahl, 100:

- die **Score-Strafe** für eine Detection: `−100` in der Wertung. Bleibt.
- der **Risikokoeffizient** der EV-Rechnung: bepreist, was es *operativ*
  kostet, einmal aufzufallen. Das ist nicht der Totalverlust, denn das
  Detection-Budget ist 3. Eine Detection verbraucht ein Drittel der
  Toleranz des Laufs.

Neu:

```
EV = (wert_des_ergebnisses × P(erfolg)) − (R × P(entdeckung)_effektiv)
R = 33     # ≈ 100 / Detection-Budget, eigener Konfigurationswert
```

`R` ist **eigenständig konfigurierbar**, nicht aus dem Budget abgeleitet.
Abgeleitet wäre eleganter, würde aber heißen, dass eine Budgetänderung die
Aggressivität stillschweigend mitverschiebt. Die Herleitung steht als
Begründung im Kommentar, der Wert im Risikoprofil.

### 2.3 Das Risikoprofil setzt zusätzlich R

§15s Profil-Zeile setzt bisher EV-Schwelle, P(detect)-Startwert und
Detection-Budget. `R` kommt dazu:

| Profil | Schwelle | P(detect) | Budget | R |
|---|---|---|---|---|
| Passiv | +20 | 0.25 | 2 | 50 |
| Normal | 0 | 0.15 | 3 | 33 |
| Aggressiv | −15 | 0.10 | 4 | 25 |

Einzeln überschreibbar, wie bisher.

---

## 3 Die korrigierte Risikotabelle

| Aktion | schaltet frei | Wert | P(erfolg) | P(detect) |
|---|---|---|---|---|
| `exploit_known_poc` | `rce_achieved` | 200 | 0.60 | 0.30 |
| `remote_exec` | `successful_login` | 75 | 0.80 | 0.60 |
| `persist` | erhält einen `successful_login` | 75 | 0.90 | 0.25 |
| `ntlm_relay` | `successful_login` über Relay | 75 | 0.40 | 0.50 |
| `lsass_dump` | `credential_captured` | 50 | 0.50 | 0.70 |
| `responder` | `credential_captured` | 50 | 0.60 | 0.55 |
| `iface_change` | ermöglicht die Wifi-Kette | 30 | 0.90 | 0.20 |
| `deauth` | `handshake_captured` | 30 | 0.70 | 0.40 |
| `device_write_unknown` | nichts Gewertetes | 0 | 0.80 | 0.30 |
| `log_clear` | nichts Gewertetes | 0 | 0.80 | 0.80 |
| `shadow_copy_delete` | nichts Gewertetes | 0 | 0.80 | 0.85 |

Nur die Spalte **Wert** ändert sich. P(erfolg) und P(detect) bleiben,
wie §10.5 sie hat.

### 3.1 Was dabei herauskommt

R = 33, Schwelle 0:

| Aktion | EV ohne | nach 1 | nach 2 | ab welcher Detection abgelehnt |
|---|---|---|---|---|
| `exploit_known_poc` | **+110** | +105 | +100 | — |
| `persist` | **+59** | +54 | +49 | — |
| `remote_exec` | **+40** | +35 | +30 | — |
| `iface_change` | **+20** | +15 | +10 | — |
| `ntlm_relay` | **+13** | +8 | +3 | 3 |
| `responder` | **+12** | +7 | +2 | 3 |
| `deauth` | **+8** | +3 | −2 | 2 |
| `lsass_dump` | **+2** | −3 | −7 | 1 |
| `device_write_unknown` | **−10** | −15 | −20 | sofort |
| `log_clear` | **−27** | −32 | −32 | sofort |
| `shadow_copy_delete` | **−28** | −32 | −32 | sofort |

Das trifft §10.6s Absicht: die Leine zieht sich messbar an, in der
richtigen Reihenfolge — der lauteste Griff zuerst — ohne den Agenten nach
dem ersten TCP-Reset vollständig zu sperren. Bei 3 Detections bricht der
Lauf ohnehin ab, der EV-Pfad muss darüber hinaus nichts leisten.

Dass Anti-Forensik und unbekannte Schreibzugriffe **dauerhaft** abgelehnt
werden, ist beabsichtigt: sie werten nichts und sind laut. Will der Operator
sie, klopft der Agent im überwachten Modus an.

---

## 4 Wogegen abzuwägen ist

Drei Punkte, die mit der Abnahme mitentschieden werden.

**`exploit_known_poc` wird mit +110 die attraktivste Aktion überhaupt** und
flippt nie. Im Full-Auto mit eingeschalteter Phase 5 wird der Agent
Exploitation allem anderen vorziehen. Das ist arithmetisch korrekt — ein
funktionierender Exploit *ist* das Wertvollste — und durch den Phase-5-
Schalter gedeckt, der standardmäßig aus ist. Wer das nicht will, setzt den
Wert auf `vuln_detected` +25, womit die Aktion wieder dauerhaft abgelehnt
wird.

**`lsass_dump` bei +2 ist extrem knapp.** Die Entscheidung hängt an der
zweiten Dezimalstelle. Inhaltlich passend — es ist laut eigener Begründung
der lauteste EDR-Auslöser und soll nach der ersten Detection wegfallen —
aber es ist keine robuste Marge.

**`remote_exec` und `persist` flippen nie.** Beide sind leise und wertvoll,
also plausibel; es heißt aber, dass die Detection-Nachführung sie nicht
bremst und nur das Budget sie stoppt.

---

## 5 Was danach zu tun ist

1. §10.5s Tabelle um „schaltet frei" und die Wertspalte ergänzen.
2. §10.8s Formel auf `R` umstellen, mit der Herleitung.
3. §15s Profil-Tabelle um `R` ergänzen und das Rechenbeispiel auf die
   geltenden Zahlen bringen: `exploit_known_poc` lautet dann
   `200×0.60 − 33×0.30 = +110.1 → proceed`.
4. `safety.RISK_TABLE` auf die Wertspalte umstellen.
5. `gate.Gate` nimmt `risk_coefficient` statt der festen 100.
6. Tests: die EV-Erwartungen in `test_agent_gate` rechnen heute mit 100 und
   müssen mitgezogen werden; ein Test pinnt die Reihenfolge der Flips, weil
   das die Eigenschaft ist, die §10.6 zusagt.

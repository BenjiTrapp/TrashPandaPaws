# Raccoon HAT — Open Engineering Questions

Status of the v1 HAT hardware sources, and the list of things that must be
resolved by a hardware engineer before this board can go to fabrication.

> **Maturity:** the KiCad sources in `kicad/` are a **concept stage** design.
> The board is not routed and the schematic is not fully connected. Do not send
> these files to a fab house. See "Source file state" below.

## Resolved

### R10 feedback divider — wrong reference voltage (fixed 2026-09-24)

`design-guide.md` §1.2 assumed a 0.8 V feedback reference for the TPS54302 and
derived `R10 = 100K × 0.8/(5 − 0.8) ≈ 19.1K`.

The TPS54302 reference is **0.596 V typical** (0.581 … 0.611 V, ±2.5%), per the
TI datasheet SLVSDF3 §6.3.7 and the TPS54302EVM-716 user's guide SLVUAP9.

| | R10 = 19.1K (was) | R10 = 13.3K (now) |
|---|---|---|
| V_OUT typ | **3.72 V** | 5.08 V |
| V_OUT over V_REF tolerance | 3.62 … 3.81 V | 4.95 … 5.21 V |
| Inside Pi 4 window (4.75–5.25 V) | **no — would not boot** | yes |

13.3 K is the value TI tabulates for a 5 V output. Changed in
`design-guide.md`, `bom.csv` and `kicad/raccoon-hat.kicad_sch`.

Root cause note: L1 = 10 µH, C11+C12 = 44 µF and C1 = 100 nF all match TI's
5 V row exactly, so only V_REF had been mis-transcribed. That consistency is
what made the error easy to overlook.

### R3 / R4 PoE signature resistors (fixed 2026-09-24)

| Part | Was | Now | Source |
|---|---|---|---|
| R4 (RDET) | 25.5 kΩ | **24.3 kΩ ±1%** | 25.5 kΩ is the *obsolete Si3402-A* value. The Skyworks A→B migration note states it "must be replaced by 24.3 kΩ 1%". |
| R3 (RCL) | 49.9 kΩ | **48.7 Ω ±1%** | RCLASS is specified in **ohms**. 48.7 Ω = Class 3 (6.49–12.95 W), which matches a Pi 4 + HAT at ~12 W. 49.9 kΩ is ~1000× too high and matches no class. |

With a 49.9 kΩ RCL the class current would be ~27 µA, so the PSE would have
classified the PD as Class 0 regardless of the documented "Class 3" intent.
Changed in `design-guide.md` and `bom.csv`. Note these values are only
meaningful once the surrounding circuit is corrected — see item 0 below.

Reference class table (AN956 Table 3 / AN1130 Table 3.4):

| Class | Power | RCLASS |
|---|---|---|
| 0 | 0.44–12.95 W | open or >681 Ω |
| 1 | 0.44–3.84 W | 140 Ω |
| 2 | 3.84–6.49 W | 75.0 Ω |
| 3 | 6.49–12.95 W | 48.7 Ω |
| 4 | 12.95–25.5 W (Type 2) | 33.2 Ω |

## Open — electrical

### 0. RESOLVED: architecture decision — Option A

**Decided 2026-09-24: drop PoE from this board and use the official Raspberry Pi
PoE+ HAT for power.** The custom PCB is reduced to what genuinely needs to be
custom: the USB 3.0 → Gigabit Ethernet tap.

Rationale is in 0a–0c below. In short: the Si3402-B is IEEE 802.3 Type 1 only
(12.95 W at the PD), which Raspberry Pi themselves describe as "not quite enough
to power the hungriest USB peripherals at the same time" — and this board *is*
that case, a Pi 4 plus a USB 3.0 Gigabit controller. Their answer was the PoE+
HAT: 802.3at, Class 4, 5 V / 4 A, 25.5 W, on 4 layers of 2 oz copper. Even a
correctly implemented Si3402-B design would have been too small.

**Resulting component set:**

| | Parts |
|---|---|
| **Dropped** | U1 (Si3402-B), U2 (TPS54302), T1, D1–D4, Q1, F1, L1, L2, C1–C4, C11, C12, R3, R4, R9, R10 |
| **Dropped — see 3c** | U5 (W25Q16) + C10 (frees LED0/LED1, OTP replaces it) |
| **Dropped — see 4 and 6** | LED1/LED2 (the new jack has its own), R1/R2 (BST integrated) |
| **Replaced — see 4** | J2: HR911105A (10/100 only) → **LPJG16402AQNL** (gigabit) |
| **Kept** | U3 (RTL8153B), **U4 (AP2112K — required, see 3d)**, Y1, J3, R7/R8, C2, C5–C9, C13/C14 |
| **To add** | U6 SY8089AAAC buck + L2 2.2uH + R5/R6 divider (item 3f), R11 RSET 2.49k 1% (item 3e), USB VBUS bulk cap, 1.0 V rail decoupling, cap on J2 pins 5/6 |
| **External** | Raspberry Pi PoE+ HAT, $20, certified |

The board no longer needs a GPIO header (J1) or a PoE connector: it draws its
~1.5 W from the USB 3.0 port it is already plugged into (USB 3.0 supplies 900 mA
at 5 V = 4.5 W). That removes the 48 V rail, the isolation barrier, the flyback
transformer, EMC filtering and the 4-layer/2 oz requirement from this project.

Consequence for the form factor: without the GPIO header this is no longer a HAT
and the 65 × 56 mm outline can shrink considerably. The outline was left at
65 × 56 mm for now since the board is unrouted anyway.

Accepted downside: two boards instead of one, which works against the covert
single-board goal. Revisit if that becomes the dominant requirement — but note
that doing so means taking on a full 802.3at isolated design (Option C).

### 0a. Why the Si3402-B could not deliver enough power

The Si3402-B is **IEEE 802.3 Type 1 only** — the datasheet states it supports
"IEEE 802.3 Type 1 (Class 3 and below) Powered Device applications", capped at
12.95 W at the PD.

Raspberry Pi's own guidance on their 802.3af PoE HAT (13 W):

> "This is enough to power a Raspberry Pi 4 at maximum load, but **not quite
> enough to power the hungriest USB peripherals at the same time.**"

This board *is* that case: a Pi 4 plus an RTL8153B USB 3.0 Gigabit controller.
Raspberry Pi's answer was the PoE+ HAT — 802.3at, Class 4, 5 V / 4 A, 25.5 W.

| | Pi PoE HAT | Pi PoE+ HAT | This design |
|---|---|---|---|
| Standard | 802.3af | 802.3af + **802.3at** | 802.3af only |
| Class | 2 | **4** | 3 (after fix) |
| Output | 5 V / 2.5 A | **5 V / 4 A** | 5 V / 3 A (claimed) |
| Max power | 15.4 W | **25.5 W** | 12.95 W at PD |
| PCB | 4 layer, 2 oz Cu | 4 layer, 2 oz Cu | **2 layer, 1 oz Cu** |

So even a *correctly implemented* Si3402-B design would be marginal here. A
Type 2 (802.3at) front end is required.

### 0b. Architecture options considered

Ranked by risk. This decision gates the schematic's power section, because it
determines which components exist at all.

**Option A — drop PoE from this board, use the official PoE+ HAT (lowest risk)**

Let the $20 certified Raspberry Pi PoE+ HAT handle power and reduce this PCB to
what genuinely needs to be custom: the USB 3.0 → Gigabit Ethernet tap.

The Raccoon board then needs no PoE and no GPIO header — it draws its ~1–1.5 W
from the USB 3.0 port it is already plugged into (USB 3.0 supplies 900 mA at 5 V
= 4.5 W). This removes the 48 V rail, the isolation barrier, the flyback
transformer, EMC filtering and the 4-layer/2 oz requirement from the project.

- Drops: U1, T1, U2, D1–D4, Q1, F1, L1, L2, C1–C6, C11, C12, R3–R10
- Keeps: U3, U4, U5, Y1, J2, J3, LEDs and their passives
- Downside: two boards, which works against the covert single-board goal

**Option B — pre-certified isolated PoE PD module**

Replace the discrete front end with a drop-in module that already contains the
signature circuit, the isolated DC/DC and 1500 V isolation (IEEE 802.3af §33.4.1
/ IEC 60950 6.2). Typically needs only two bridge rectifiers and a bulk cap.

Caveat found while researching: the obvious Silvertel Ag9900-class candidates are
**not** sufficient at 5 V — the Ag9905M is 9 W at 70 °C and 6 W at 85 °C. A
5 V / 4 A 802.3at-capable module is needed, so the part still has to be selected
and its availability confirmed. No part number here is a recommendation yet.

**Option C — discrete 802.3at design from a vendor reference**

Select a Type 2 PD controller and build from its reference design. Highest effort
and risk: isolated flyback, snubber, creepage/clearance, EMC. Realistically also
forces 4 layers and 2 oz copper — which is exactly what Raspberry Pi needed.

If this route is taken, Skyworks offers free schematic and layout review through
their power group. Use it.

### 0c. Defects in the existing Si3402-B circuit (for the record)

Kept for the record. Verified against the Si3402-B datasheet (Table 8), Skyworks
AN956, AN1130, the Si3402-A→B migration note and both EVB user's guides.

**Every pin number in the schematic symbol is wrong — 0 of 16 match the part:**

| Pin | Datasheet | Symbol in repo |
|---|---|---|
| 1 | EROUT | VDD_IN |
| 2 | SSFT (n.c.) | DET |
| 3 | VDD | RCLASS |
| 4 | ISOSSFT (n.c.) | VSS1 |
| 5 | PLOSS | PWRGD |
| 6 | RDET | VIN+ |
| 7 | HSO | VIN- |
| 8 | RCL | COMP |
| 9 + PAD | VNEG + thermal pad | GATE |
| 10 | SP2 | DRAIN |
| 11 | SP1 | SOURCE |
| 12 | VPOSF | VDD |
| 13 | CT2 | FB |
| 15 | VSSA | FREQ |
| 16 | VPOSS (n.c.) | EN |
| 21 | *does not exist* | EP |

Consequences, in order of severity:

1. **`PLOSS` → `TPS54302.EN` would destroy the TPS54302.** PLOSS is an
   open-drain pin pulled to `VPOS`, i.e. up to 57 V.
2. **The architecture is a double conversion.** The Si3402-B integrates the PWM
   controller and the switching FET and generates the regulated output itself,
   either as an isolated flyback (via T1) or a non-isolated buck (via an
   inductor). A downstream TPS54302 buck is not part of either topology. The
   documented chain `U1 → T1 → U2 → 5V` matches neither reference design.
3. **An isolated design is missing its feedback path.** `EROUT` drives an
   opto-coupler, with a TLV431 as the secondary-side reference. Neither part is
   in the BOM, so the loop cannot close.
4. **Q1 is unnecessary.** The hotswap FET is internal, with two-step inrush
   limiting (140 mA typ.). There is no gate output on the device.
5. **D3/D4 are unnecessary and undersized.** `SP1`/`SP2` are polarity-insensitive
   HV inputs behind integrated bridges. BAT54S is a 200 mA small-signal diode and
   cannot carry a ~12 W PoE path.
6. **D2 duplicates an integrated function** — the transient surge suppressor is
   on-chip.
7. **>7 W requires external Schottky bridge diodes** to spread heat (AN956
   design checklist 1.d). This board targets ~12 W and has none. D1 (MBRS340) is
   most plausibly the intended output rectifier, but it is never connected.
8. **`VSS2` must be tied externally to `HSO`** — a mandatory connection that
   appears nowhere.
9. **The `VNEG` thermal pad needs ≥9 thermal vias** to a plane. The PCB has zero
   vias.
10. **`CDET` is missing.** The PD must present 50–120 nF at the input; ~100 nF
    nominal.
11. **No minimum load.** Skyworks recommends ≥250 mW to prevent switcher pulsing
    and false disconnect below 10 mA draw.

**Recommendation:** do not incrementally patch this. Skyworks strongly recommends
starting from their EVB design — `Si3402B-ISO-EVB` (isolated) or `Si3402B-EVB`
(non-isolated) — and offers a free schematic and layout review through their
power group. For a HAT that shares ground with the Pi, the isolated flyback is
the topology the official Pi PoE HAT uses.

A decision is needed on isolated vs. non-isolated before the schematic can be
completed, because it determines whether T1, the opto-coupler and TLV431 are in
or out.

### 1. Feed-forward capacitor across R9

TI's 5 V reference design places a ~75 pF capacitor across the upper divider
resistor to improve phase margin. This board has no such component. Decide
whether to add it before fabrication.

### 2. PoE front-end is not specified

`design-guide.md` §1.1 documents only part of the SI3402-B circuit. The
following are undefined in every source file and cannot be derived from the
documentation:

| Item | What is missing |
|---|---|
| T1 (750342460) | No pin/winding connections given at all. PCB footprint has 8 pads. |
| U1 SI3402-B | 10 of 16 pins undocumented: `VIN+ VIN- COMP DRAIN SOURCE VDD FB FREQ EN EP` |
| D1 (MBRS340) | Appears in the block diagram, never connected anywhere |
| Q1 (SI2302CDS) | Only the gate is documented (`U1.GATE`); source and drain undefined |
| L2 (4.7 µH) | Present in BOM, schematic and block diagram; no documented function |
| C15 … C19 | Present in schematic and PCB; not mentioned in the guide |
| `POE_VOUT` net | The node between U1/T1 and `U2.VIN` is ambiguous — the block diagram routes power through T1, but T1 has no defined pinout |

This is the isolated 48 V section. It needs to be designed against the
SI3402-B datasheet and reference application, with creepage/clearance for
mains-adjacent PoE isolation, and then reviewed.

### 3. RESOLVED (pinout) / TODO (footprint): the RTL8153B was mis-specified

Verified against the RTL8153B-VB-CG datasheet (rev 1.0 / 1.4) and Realtek's
product page on 2026-09-24.

#### 3a. Wrong package

Realtek states a **40-pin QFN, 5 × 5 mm** ("40-pin QFN 'Green' package",
`QFN40_5X5MM_EP`). The repo has:

| | Repo | Datasheet |
|---|---|---|
| BOM package | QFN-48 | **QFN-40** |
| PCB footprint | `QFN-48_U3`, 49 pads, 7 × 7 mm | **5 × 5 mm** |
| Symbol pin numbers | up to 42 | **1…40** |

The footprint is the wrong pin count *and* the wrong body size, so it must be
replaced outright.

#### 3b. Wrong pinout

The MDI pairs are not contiguous — pins 3 and 8 are `AVDD10`, which the repo
symbol does not account for:

| Signal | Datasheet | Repo symbol |
|---|---|---|
| MDIP0 / MDIN0 | **1 / 2** | 11 / 10 |
| MDIP1 / MDIN1 | **4 / 5** | 8 / 7 |
| MDIP2 / MDIN2 | **6 / 7** | 5 / 4 |
| MDIP3 / MDIN3 | **9 / 10** | 2 / 1 |
| U3SSTXN / U3SSTXP | **12 / 13** | 21 / 22 |
| U3SSRXN / U3SSRXP | **15 / 16** | 18 / 19 |
| U2DM / U2DP | **17 / 18** | 15 / 16 |
| CKXTAL1 / CKXTAL2 | **35 / 36** | 33 / 34 |
| SPICSB | **32** | 39 |
| SPISDO | **24** | 41 |
| SPISDI | **25** | 42 |
| SPISCK | **30** | 40 |

The signal pins above come from explicit datasheet tables and are reliable. The
**power and regulator pins are not yet confirmed** — the pin-assignment figure
did not extract cleanly from the PDF, so `AVDD10`, `AVDD33`, `DVDD10`, `DVDD33`,
`VDD5`, `REGOUT`, `DVDD10_UPS`, `RSET` and `GND` positions must be read off the
datasheet figure directly before the symbol is finalised. Do not infer them.

#### 3c. SPI flash conflicts with the LEDs — and is probably unnecessary

The LED outputs are **shared pins**:

| Pin | Shared functions |
|---|---|
| 32 | `LED0` / `SPICSB` |
| 30 | `EESK` / `LED1` / `SPISCK` |
| 24 | `EEDO` / `LED2` / `SPISDO` / `LANWAKEB` / `GPIO` |

Only one function per pin can be active at a time. Populating the W25Q16 SPI
flash therefore **costs LED0 and LED1** — exactly the two LEDs the design guide
wires to R7/R8. As drawn, the design cannot have both.

It is also likely the flash is not needed at all: Realtek states the part has
"embedded One-Time-Programmable (OTP) memory that can replace the external
EEPROM". The SPI flash interface is for PXE boot ROM images, which this
application does not use.

**Recommendation: drop U5 and C10, and keep the LEDs.** That removes the pin
conflict and a part.

#### 3d. The external 3.3 V LDO is REQUIRED — earlier suspicion was wrong

An initial reading suggested the chip's "built-in switching regulator and LDO
regulator" might make U4 (AP2112K) redundant. **Checking the datasheet showed the
opposite**, which is why it was verified rather than acted on:

- `VDDREG33` (26) is an **input** — "Digital 3.3V Power Supply for
  Switching/LDO Regulator", not an output.
- §6.15 Note 1: "The embedded LDO is designed for the RTL8153B-VB internal use
  only. Do not provide this power source to other devices."
- `AVDD33` (11, 20, 39, 40) and `DVDD33` (23, 33) all need 3.3 V from outside.

So the chip needs **both** 5 V and 3.3 V supplied externally. With Option A the
only input is USB VBUS at 5 V, so **U4 stays** and its capacitors with it.

The internal switching regulator generates only the 1.0 V core rail.

#### 3e. Two mandatory connections are missing entirely

| Requirement | Source | Status in repo |
|---|---|---|
| `REGOUT` (28) must be externally wired to `DVDD10` (34), `AVDD10` (3, 8, 37), `U3VDD10` (14), `U2VDD10` (19) | datasheet §6.14, explicit | **absent** — without it the chip has no 1.0 V core supply. Only applies if the internal SWR is used; see 3f. |
| `RSET` (38) needs an external reference resistor | pin table §5.6 | **absent** — no such part in the BOM |

**`RSET` value resolved: 2.49 kΩ 1% to GND.** The RTL8153B-VB datasheet gives no
value and defers to a reference schematic that is not published. Traced from
Olimex's OSHW design instead: `U3.RSET → R8.1`, `R8.2 → GND`, `R8 = 2.49k 1%
0402`. The pin sets an internal current reference, which is a
variant-independent function, so this is a sound starting value — but it comes
from the **VC** variant and is not confirmed for the **-VB**. Verify on first
build.

§6.14 additionally warns the switching regulator "requires a well-designed PCB
layout in order to achieve good power efficiency and lower the output voltage
ripple and input overshoot" — relevant given the board is currently 2-layer with
zero vias.

The full verified pinout is now recorded in `design-guide.md` §2.1.

### 3f. RESOLVED: external buck on a 4-layer board

**Decided 2026-09-25: `ENSWREG` → GND, internal switching regulator disabled,
1.0 V supplied by an external buck, on a 4-layer stackup.** Chosen for lowest
risk and a robust layout.

`ENSWREG` (pin 25, shared with `SPISDI`) is a power-on latch: 3.3 V enables the
internal switching regulator, 0 V disables it and requires external 1.0 V.
Olimex take the same route in their shipping design.

Why external, even though it costs parts:

- [RTL-614] warns the internal SWR "requires a well-designed PCB layout in order
  to achieve good power efficiency and lower the output voltage ripple and input
  overshoot". An external buck removes that dependency entirely.
- 4 layers were needed anyway for USB 3.0 impedance control, so the marginal
  cost of the decision is small.
- `REGOUT` (28) is left unconnected, which also retires the mandatory
  REGOUT-fanout wiring requirement from item 3e.

**Dimensioning, computed rather than copied:**

| Part | Value | Basis |
|---|---|---|
| U6 | SY8089AAAC, SOT-23-5 | 2.7–5.5 V in, 2 A cont. / 3 A peak, 1 MHz fixed. Same part Olimex use for this role. |
| R5 / R6 | **10.0 kΩ / 15.0 kΩ, 1 %** | `Vout = 0.6 × (1 + R5/R6) = 1.000 V`. Datasheet recommends 10 k…1 M. |
| L2 | **2.2 µH** | `L = Vout(1 − Vout/Vin,max)/(Fsw·Iout,max·40%)` = 2.05 µH at a 1 A design point, Fsw = 1 MHz. |

Tolerance check: with `VREF` = 0.588 / 0.600 / 0.612 V and 1 % resistors, the
output lands between **0.972 V and 1.028 V** — inside the 0.95–1.05 V window of
[RTL-DS] table 21, with margin on both sides.

> **Do not copy Olimex's divider.** They use R12 = R15 = 1.1 kΩ, a 1:1 ratio,
> which yields 0.6 × 2 = **1.200 V**. That suits their RTL8153**VC**; on a
> **-VB** it would over-volt the core rails by 20 %.

Two independent cross-checks came out consistent: the 1 A design point gives
2.05 µH → 2.2 µH, which is exactly the inductor Olimex ship, and their part
choice matches. The 1.0 V rail current is not specified in [RTL-DS], so 1 A is a
conservative assumption to confirm by measurement on the first build.

### 3g. Stackup

4 layers, 1.6 mm, 1 oz outer:

| Layer | Use |
|---|---|
| F.Cu | signals — USB 3.0 pairs, MDI pairs, buck hot loop |
| In1.Cu | **solid GND plane** — unbroken reference under every high-speed pair |
| In2.Cu | power — +5V, +3V3, +1V0 |
| B.Cu | signals plus a second GND pour |

Impedance targets: **90 Ω** differential for USB 3.0 SuperSpeed and USB 2.0
D+/D−, **100 Ω** differential for the MDI pairs, both referenced to In1. Ask the
fab for a stackup that hits these at their actual core/prepreg thicknesses rather
than assuming a trace geometry.

Full rule list is in `netlist.yaml` under `stackup.rules`.

### 4. RESOLVED: J2 replaced with a gigabit MagJack

**The HR911105A was a 10/100Base-TX part** — its datasheet is titled "…Integrated
Magnetics and LED for **10/100Base-TX** NIC Applications", corroborated by four
independent listings. 1000BASE-T uses all four pairs bidirectionally and each
needs its own transformer and common-mode choke; a 10/100 MagJack has them on
two. The part physically could not pass gigabit.

Consequences it would have had:

1. The link would have negotiated at **100 Mbit/s** — a bottleneck in any modern
   network.
2. **An OPSEC failure:** inserting the implant would visibly drop a gigabit
   switch port to 100 Mbit, an immediately noticeable anomaly.
3. The "Gigabit link on J2 (1000BASE-T negotiation)" test item was unachievable.

**Replacement: LINK-PP LPJG16402AQNL.** Verified against LINK-PP drawing
LP11021122 rev A (both sheets read from the rendered drawing), the part LINK-PP
title as "RJ45 Connector With 1000 Base-TX Integrated Magnetic", UL file E484635.
It is the same jack Olimex use in their OSHW USB-GIGABIT, which reaches
950 Mbit/s over USB 3.0.

| Property | Value |
|---|---|
| Speed | 10/100/1000BASE-T, 8-core magnetics on all four pairs |
| Turns ratio | 1CT:1CT ±2% |
| OCL | 350 µH min |
| Insertion loss | −1.0 dB max, 0.9–100 MHz |
| Crosstalk / CMR | −25 dB / −30 dB min, 1–100 MHz |
| Hipot | **1500 Vrms min** — satisfies IEEE 802.3 isolation |
| AutoMDX | yes |
| PoE | no — data only, which is fine since PoE moved to the PoE+ HAT |
| Temperature | −40 to +85 °C |
| Mounting | THT, right-angle, tab-up, 21.25 × 15.95 × 13.45 mm |

Verified pinout, now recorded in `netlist.yaml`:

| PHY-side pin | Signal | Cable pin |
|---|---|---|
| 1 / 2 | TD1± | J1 / J2 |
| 3 / 4 | TD2± | J3 / J6 |
| 5, 6 | PHY-side centre-tap common | — |
| 7 / 8 | TD3± | J4 / J5 |
| 9 / 10 | TD4± | J7 / J8 |
| 11 / 12 | right LED, bi-colour (11+/12− green, 11−/12+ orange) | — |
| 13 / 14 | left LED, yellow (13 = anode) | — |

The cable-side mapping is the standard 1000BASE-T assignment, so the pair
grouping the design guide intended is correct.

Footprint to build: 10 × ⌀0.90 signal pins in two rows at 1.27 mm pitch and
2.54 mm row spacing, 4 × ⌀1.02 LED pins, 2 × ⌀1.70 shield posts, 2 × ⌀3.25
T-posts, 15.75 mm overall span.

### 5. D3 / D4 package vs. usage

The guide uses D3 and D4 as single series diodes on the VC2+/VC2− rails, but
specifies BAT54S — a *dual* diode in SOT-23. Either the part or the usage is
wrong. Decide on package and pinout.

> Moot under Option A — D3/D4 are PoE-stage parts and are dropped. Kept for the
> record in case a later revision brings PoE back onto the board.

### 6. RESOLVED: Bob Smith termination is integrated in the new jack

`bom.csv` listed `R1-R2, 2, 75R, "75 Ohm Ethernet Termination"`, which appeared
in neither the schematic nor the PCB — and two resistors would have been wrong
anyway, since 1000BASE-T terminates all four pairs.

**The LPJG16402AQNL integrates the whole BST network.** Read from its schematic
sheet: 4 × 75 Ω from the cable-side centre taps to a common node, then
1000 pF / 2 kV to SHIELD. No external termination resistors or capacitor are
needed. R1–R4 are dropped from the design.

What *does* need attention: jack pins 5 and 6 are the **PHY-side** centre-tap
common. Bypass them to GND with a capacitor placed close to the PHY; do not
leave them floating.

Note on numbering: the PCB originally numbered its eight resistors `R1…R8`
while the guide and BOM used `R3…R10`. The PCB was renumbered to `R3…R10` on
2026-09-24 to match.

### 7. W25Q16 HOLD# pin

§2.2 documents CS#, CLK, DI, DO, WP#, VCC and GND but not `HOLD#` (pin 7),
which must not float. Normally tied to VCC.

### 8. J1 GPIO pins 27/28 (ID_SD / ID_SC)

Documented as "optional HAT EEPROM" but no EEPROM exists in the BOM. Either add
the EEPROM (required for a compliant HAT ID) or leave the pins unconnected and
drop the claim.

## Open — source file state

Findings from a structural audit of the KiCad files (2026-09-24). KiCad was not
available to run ERC/DRC; these were established by parsing the files.

| File | Issue |
|---|---|
| `raccoon-hat.kicad_pcb` | ~~No net table; all 304 net references used the string form~~ — **fixed 2026-09-24** by `tools/fix_pcb_nets.py`. The file now carries a 40-entry net table (net 0 + 39 nets), integer net IDs on all 228 pads and 73 segments, and `net_name` on all 3 zones. |
| `raccoon-hat.kicad_sch` | Effectively unconnected: 47 symbols, 10 wires, of which 19 of 20 endpoints land on empty canvas. 0 junctions, 0 power symbols. 15 labels, none attached to a wire. 41 of 47 symbols have no footprint assigned. Netlist export would be empty. |
| Component sets | ~~PCB numbers its resistors R1…R8 where the guide and BOM use R3…R10~~ — **fixed 2026-09-24**, the PCB now uses R3…R10. Still missing from the PCB: `D1 D2 D3 D4 L2 Q1` — all PoE-stage parts, deliberately left out pending the item 0 decision. |
| `raccoon-hat.kicad_pro` | Declares 4 sheets (Root + 3 sub-sheets); only one flat sheet file exists. `Ethernet` net class has no diff-pair width/gap, so there are no 100 Ω MDI or 90 Ω USB 3.0 rules. |
| Footprints | No courtyards and almost no silkscreen/fab geometry, so courtyard DRC cannot run. |
| Layout | 73 track segments and 0 vias for 228 pads, everything on `F.Cu`. The board is not routed. |

### Value conflicts between `design-guide.md` and the schematic

The guide is treated as authoritative *where a datasheet confirms it*. Cross-checking
found one case where the guide is wrong and the schematic is right, so "the guide
wins" is not applied blindly.

**Resolved (schematic corrected 2026-09-24):**

| Ref | Was | Now | Why |
|---|---|---|---|
| R3 | 330 R | **48.7 Ω** | RCLASS Class 3 per AN956 Table 3 |
| R4 | 330 R | **24.3 K** | RDET for Si3402-**B** per the A→B migration note |
| R5 | 25.5 k | **10 K** | SPI CS# pull-up, guide §2.2; R6 already 10 K |
| R7 | 10 k | **1 K** | LED series. At 10 k the LED gets (3.3−2.0)/10k = 0.13 mA — effectively invisible. 1 K gives 1.3 mA. |
| R8 | 10 k | **1 K** | same |
| R10 | 19.1 K | **13.3 K** | see "Resolved" above |

**Guide is wrong — schematic kept:**

| Ref | Guide | Kept | Why |
|---|---|---|---|
| C6 | 100 nF | **10 µF** | AP2112K output cap. A 600 mA LDO needs ≥1 µF on the output for loop stability; 100 nF would risk instability. Following the guide here would have made the design worse. The BOM had C6 lumped into a 100 nF group; that row was split so C6 now carries 10 µF. |

**Also resolved:**

| Ref | Was | Now | Why |
|---|---|---|---|
| C8 | schematic 10 µF | **100 nF** | RTL8153B VDD33 decoupling. Guide and BOM both say 100 nF, which is correct for high-frequency decoupling; the schematic was the outlier. |

**Still unresolved — these belong to the PoE/buck section and may disappear
entirely depending on the item 0 decision, so they were deliberately not touched.
`tests/check_kicad.py` reports them as warnings rather than failures:**

| Ref | Guide | Schematic | BOM | Role |
|---|---|---|---|---|
| C1 | 100 nF | 100 µF | 10 µF | TPS54302 bootstrap — all three disagree |
| C3 | 100 µF | 100 nF | 100 µF | PoE input bulk |
| C4 | 100 µF | 22 µF | 100 µF | TPS54302 VIN |
| C11 | 22 µF | 10 µF | 22 µF | TPS54302 output |
| C12 | 22 µF | 100 nF | 22 µF | TPS54302 output |
| C15 … C19 | not mentioned | present | absent | unknown function |

`C9` is worth resolving independently of the PoE decision — DVDD12 is the
RTL8153B's internal LDO output and survives every option. Schematic and BOM both
say 100 nF; only the guide says 10 µF. An internal-LDO bypass usually wants the
larger value, so confirm against the RTL8153B datasheet.

## Footprints

| Part | Footprint | Status |
|---|---|---|
| U3 | `Package_DFN_QFN:QFN-40-1EP_5x5mm_P0.4mm_EP3.6x3.6mm` | **KiCad standard.** Matches the datasheet package table exactly: D/E = 5.00 BSC, e = 0.40 BSC, D2/E2 = 3.60 nom (3.45–3.75), JEDEC MO-220. Confirm the library name resolves in your KiCad install — it could not be checked here. |
| J2 | `raccoon:RJ45_LPJG16402AQNL` | **Built** — see below. |
| U4, U6 | `Package_TO_SOT_SMD:SOT-23-5` | KiCad standard. |
| L2, R*, C* | KiCad standard 0402/0603/0805/1210 | — |
| Y1 | `Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm` | Placeholder — depends on the crystal chosen (see item on load caps). |
| J3 | `raccoon:USB-A_3.0_Plug` | **TODO** — not built yet. No good KiCad standard exists for a USB 3.0 A-plug; needs the chosen connector's drawing. |

### J2 footprint — how the coordinates were established

The mechanical drawing is a raster scan with no extractable text, and reading
hole positions off it by eye was not reliable enough — a wrong THT position
means the part does not fit. So the vendor **STEP model** was parsed instead:
cylindrical surfaces were grouped by diameter and their axis positions read out.

The diameter clusters fell out cleanly as 0.90 (10×), 1.02 (4×), 1.70 (2×) and
3.20 (2×), matching the drawing's callouts. Every dimension then cross-checked:

| Dimension | STEP model | Drawing |
|---|---|---|
| Signal pin span | 11.43 | 11.43 |
| Row pitch | 2.54 | 2.54 |
| T-post span | 11.43 | 11.43 |
| LED pin span | 13.45 | 13.45 |
| Shield tab span | 15.75 | 15.75 |
| LED pin vertical pitch | 2.03 | 2.03 |

All six agree, so the geometry is considered established rather than estimated.

Pin assignment: row at y = −8.89 carries pins 10, 8, 6, 4, 2 (left to right);
row at y = −6.35 carries 9, 7, 5, 3, 1. LED pins 13/14 on the left at x = −6.725,
11/12 on the right at x = +6.725. Shield tabs are plated and go to the shield net;
the ⌀3.25 T-posts are plastic and therefore NPTH with no pad.

Geometry check: smallest copper-to-copper gap is 0.308 mm (pad 11 to the adjacent
T-post hole), above a typical 0.2 mm fab minimum.


| Script | Purpose |
|---|---|
| `tools/fix_pcb_nets.py` | Repairs the PCB net encoding (net table, integer ids, zone `net_name`) and keeps resistor numbering aligned. Idempotent; `--check` for a dry run. |
| `tests/check_kicad.py` | Structural regression check across schematic, PCB and BOM: net encoding, reference-designator agreement, value agreement, balanced parentheses. Exit code 0/1, so it is CI-friendly. Known gaps and deferred conflicts are declared in the script and reported as warnings. |

Neither replaces KiCad's ERC/DRC, which remains the authority and has **not**
been run — KiCad was not available in the environment where these checks were
written.

### Naming

`design-guide.md` §3.4 calls the PoE input connector **J14**, which is the
Raspberry Pi's own designator for its PoE header. The mating connector on this
board needs its own reference (`J4`); no such part currently exists in the
schematic, PCB or BOM.

## Tooling

| Script | Purpose |
|---|---|
| `tools/fix_pcb_nets.py` | Repairs the old PCB's net encoding. Idempotent, `--check` for a dry run. |
| `tools/gen_schematic.py` | Generates `kicad/raccoon-tap.kicad_sch` from `netlist.yaml`. Deterministic UUIDs, so regenerating gives a stable diff. Self-contained symbols. |
| `tests/check_netlist.py` | Validates `netlist.yaml`: shorts, floating pins, non-existent refs/pins, power inputs not on a rail, nets with under two endpoints. **Run this before generating.** |
| `tests/check_kicad.py` | Structural regression check across schematic, PCB and BOM. |

Neither replaces KiCad's ERC/DRC, which remains the authority and has **not**
been run — KiCad was not available in the environment where these were written.

### Verification done on the generated schematic

The netlist was reconstructed *from* the generated `.kicad_sch` — pin positions
computed from the symbol definitions, wires traced as a graph, labels resolved —
and compared against `netlist.yaml`:

```
Wire endpoints: 262 | on a pin: 131 | on a label: 131
Nets expected: 28 | reconstructed: 28
ALL NETS IDENTICAL
```

For contrast, the same measurement on the old `raccoon-hat.kicad_sch`:

| | old | new |
|---|---|---|
| Wires | 10 | 131 |
| Endpoints landing on a pin | 1 | 131 |
| Endpoints landing nowhere | 19 | 0 |
| Diagonal wires | 7 | 0 |
| Labels attached to a wire | 0 of 15 | 131 of 131 |
| Symbols without a footprint | 41 of 47 | 4 of 37 (the power symbols) |

`check_netlist.py` earned its place immediately: on first run it caught two
shorts and a floating pin that I had introduced by swapping the anode and
cathode of the jack's LEDs.

## ERC — now run with the real tool

KiCad 10.0.6 was installed on 2026-09-25, so `kicad-cli` is available and the
"ERC has not been run" caveat that appeared throughout this document is retired
for the schematic.

```
kicad-cli sch erc --severity-all --exit-code-violations kicad/raccoon-tap.kicad_sch
→ ** ERC messages: 0  Errors 0  Warnings 0
```

First run reported **77 violations**. All of them were real, and fixing them
found genuine mistakes my own structural checks could not see:

| Count | Kind | Cause and fix |
|---|---|---|
| 5 | error `pin_to_pin` | Two power outputs or two signal outputs on one net. I had declared connector pins with directions, as if a connector sourced or sank signals. Connectors are pass-through → all J3 signal and GND pins are now `passive`, with only VBUS left as `power_out`. |
| 2 | error `pin_not_driven` | Same root cause: J3's SSTX pins were declared `input`, so ERC wanted a driver for them. |
| 35 | warning `lib_symbol_issues` | `lib_id` carried no library prefix. The generator now also emits `kicad/raccoon.kicad_sym` and uses `raccoon:` prefixed ids, with a project `sym-lib-table`. |
| 33 | warning `footprint_link_issues` | No global library tables — KiCad had never been launched. Installed from the shipped templates, plus a project `fp-lib-table` for the `raccoon` footprint library. |
| 1 | warning `footprint_link_issues` | `raccoon:USB-A_3.0_Plug` did not exist. Resolved by picking a real part instead of drawing one. |

A second lesson: adding a power symbol to a rail that a regulator or connector
already drives *causes* an error rather than silencing one. The generator now
emits a power flag only for rails with no `power_out` pin on them — here that is
GND and +1V0, while +5V (from J3 VBUS) and +3V3 (from U4 VOUT) already have
real drivers.

### J3 connector: USB-A, and why not USB-C

Decided 2026-09-25 to keep USB-A. The Pi 4's USB-C port carries data, but only as
**USB 2.0 OTG** via the BCM2711's dwc2 controller — USB 3.0 at 5 Gbit/s exists
only on the two blue Type-A ports behind the VL805. Olimex measure ~320 Mbit/s
over USB 2.0 with this same PHY against 950 Mbit/s over USB 3.0, so USB-C into
the Pi's own port would have thrown away the gigabit capability that fixing J2
just restored. A USB-C *receptacle* plus a C-to-A cable would keep full speed but
needs a SuperSpeed mux to serve both plug orientations, since the RTL8153B has
only one SuperSpeed lane pair — otherwise the board works in one orientation
only, which is a poor property for field deployment.

Part chosen: **Würth 692112030100**, USB 3.0 Type-A SMT plug, horizontal, using
the KiCad-maintained footprint `Connector_USB:USB3_A_Plug_Wuerth_692112030100_Horizontal`.
Its pads 1–9 match the standard USB 3.0 Type-A pinout already in the netlist; the
shield pads are named `SH`, so J3's shield pin was renamed to match.

### Project files added

| File | Purpose |
|---|---|
| `kicad/raccoon-tap.kicad_pro` | Project with net classes `Default`, `USB3` (90 Ω target), `MDI` (100 Ω target), `Power`, and netclass patterns assigning them automatically by net name. |
| `kicad/raccoon.kicad_sym` | Generated symbol library. |
| `kicad/sym-lib-table`, `kicad/fp-lib-table` | Register the project's symbol and footprint libraries. |

> The diff-pair width and gap values in the net classes are **starting points**,
> not verified geometry. They must be replaced with numbers from the
> fabricator's impedance calculator for their actual 4-layer stackup.

## PCB — generated and DRC-checked, not routed

`tools/gen_pcb.py` builds `kicad/raccoon-tap.kicad_pcb` through KiCad's own
`pcbnew` API, so the file is written by KiCad rather than hand-assembled. It must
run under KiCad's bundled Python:

```
/Applications/KiCad/KiCad.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3 \
  tools/gen_pcb.py
kicad-cli pcb drc --severity-all kicad/raccoon-tap.kicad_pcb
```

What it produces: 58 × 36 mm outline, 4-layer stackup (F.Cu signals, In1 solid
GND, In2 power, B.Cu GND pour), all 33 footprints loaded from their real
libraries and placed by signal flow, all 29 nets created and assigned to pads,
a 3 × 3 thermal via array under U3's exposed pad, and GND stitching around the
perimeter.

### DRC progress

| Run | Violations | What changed |
|---|---|---|
| first | 372 | — |
| 2 | 263 | outline actually drawn, placement spread out, via sizes made manufacturable |
| 3 | 269 | went *up*: removing the F.Cu pour fixed 77 clearance errors but my C1/C2 moves created new collisions |
| 4 | 259 | collision check added to the generator itself |
| final | **43** | working DRC rule for fine-pitch pads, last overlaps cleared, silkscreen policy |

Final state:

```
** Found 43 DRC violations **     (41 via_dangling + 2 silk_over_copper, all warnings)
** Found 134 unconnected pads **  (nothing is routed yet - expected)
** Found 0 Footprint errors **
```

**Zero errors.** The 41 dangling vias are the GND stitching array, which connects
plane-to-plane and will resolve once routing exists. The 134 unconnected pads are
simply the unrouted state.

### Mistakes DRC caught that my own checks could not

1. **`add_outline()` was defined but never called.** DRC said "board has an
   invalid outline: no edges found on Edge.Cuts". My structural checks had no
   concept of a board outline, so this would have gone unnoticed.
2. **Four shorting_items** — pads of different nets physically touching, caused by
   footprints overlapping. Symptoms of bad placement, not of a bad netlist.
3. **Thermal vias were unmanufacturable** — 0.45 mm diameter on a 0.25 mm drill
   gives a 0.10 mm annular ring, under the 0.13 mm board minimum, and the drill
   was under the 0.3 mm minimum. Now 0.6/0.3 on a 1.1 mm grid.
4. **J3's pads were off the board.** The USB plug footprint has its pads 10.85 mm
   behind the origin and its shell extending the other way, so the part had to be
   rotated 180° with its origin *outside* the outline — the shell overhangs the
   edge, which is what a plug does.
5. **A fix that made things worse.** Adding an F.Cu ground pour to silence
   `via_dangling` created 77 clearance errors against U3's fine-pitch pads, and
   contradicted the stackup where F.Cu is a signal layer. Removed.
6. **`A.Fp_Reference` silently matches nothing** in KiCad 10 custom rules. The
   first rule file looked correct and changed nothing. Probing with a
   deliberately broad rule proved the file *was* being read, which narrowed it to
   the condition syntax; `A.memberOfFootprint()` works.

### The custom DRC rule

`kicad/raccoon-tap.kicad_dru` relaxes clearance **only between pads of the same
footprint**. U3 is a QFN-40 on 0.40 mm pitch: pad-to-pad gaps are around 0.15 mm
and the exposed pad is closer still, while the Power netclass asks for 0.30 mm.
That spacing is set by the package, not by the layout. Clearance from U3's pads to
anything else keeps the full netclass value, so no board-level rule is weakened.

### Still to do on the PCB

| Item | Note |
|---|---|
| **Routing** | Not done, and deliberately not autorouted. KiCad has no built-in autorouter; FreeRouting is external and is documented to ignore inner layers on 4-layer boards, routing GND and VCC as surface tracks. The difficulty here is 7 differential pairs, where autorouters do not hold intra-pair spacing, length matching or reference-plane continuity. Use KiCad's interactive differential-pair router. |
| **Diff-pair geometry** | The width/gap values in the net classes are placeholders. Get real numbers from the fab's impedance calculator for their actual 4-layer stackup before routing. |
| **In2 power plane** | Generated as a single +3V3 pour. Split it into +5V, +3V3 and +1V0 islands by hand. |
| **Placement review** | Placement is by signal flow and passes courtyard checks, but has not been optimised. In particular the decoupling caps should end up closer to their supply pins than a generator can reasonably decide. |
| **J2 orientation** | Check against the mechanical drawing that the RJ45 opening faces the board edge. |
| **SHIELD tie** | J2's shield net needs a deliberate connection strategy — see `netlist.yaml` `design_notes.shield_tie`. |

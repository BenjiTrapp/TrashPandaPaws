# Pre-Power Continuity Check — Raccoon HAT v1

Manual multimeter checks **before** applying power for the first time.
Set multimeter to continuity/diode mode.

## 1. Short Circuit Check (must NOT beep)

| Probe A     | Probe B     | Expected | Notes                         |
|-------------|-------------|----------|-------------------------------|
| GND (MH1)   | +5V (C4+)  | OPEN     | Main 5V rail                  |
| GND (MH1)   | +3V3 (C8+) | OPEN     | 3.3V LDO output              |
| GND (MH1)   | +48V (C1+) | OPEN     | PoE input rail                |
| +5V (C4+)   | +3V3 (C8+) | OPEN     | Rails must not be shorted     |
| USB D+ (J3) | USB D- (J3) | OPEN     | USB data lines                |

## 2. Ground Continuity (MUST beep)

| Probe A     | Probe B     | Expected | Notes                         |
|-------------|-------------|----------|-------------------------------|
| MH1 pad     | MH2 pad     | SHORT    | GND pour connects all corners |
| MH1 pad     | MH3 pad     | SHORT    |                               |
| MH1 pad     | MH4 pad     | SHORT    |                               |
| MH1 pad     | J2 shield   | SHORT    | RJ45 shield to GND            |
| MH1 pad     | J3 shield   | SHORT    | USB shield to GND             |
| MH1 pad     | U1 EP       | SHORT    | SI3402-B exposed pad          |
| MH1 pad     | U3 EP       | SHORT    | RTL8153B exposed pad          |

## 3. Power Rail Continuity (MUST beep)

| Probe A          | Probe B          | Expected | Net        |
|------------------|------------------|----------|------------|
| F1 pin 2         | U1 pin 1         | SHORT    | +48V_POE   |
| U2 pin 6 (SW)    | L1 pin 1         | SHORT    | SW_NODE    |
| L1 pin 2         | C4+              | SHORT    | +5V        |
| C4+              | U4 pin 1 (VIN)   | SHORT    | +5V        |
| U4 pin 5 (VOUT)  | C8+              | SHORT    | +3V3       |
| C8+              | U3 VDD33         | SHORT    | +3V3       |

## 4. Signal Path Check

| Probe A          | Probe B          | Expected | Net        |
|------------------|------------------|----------|------------|
| U3 SPI_CLK       | U5 pin 6 (CLK)   | SHORT    | SPI_CLK    |
| U3 SPI_MOSI      | U5 pin 5 (DI)    | SHORT    | SPI_MOSI   |
| U3 SPI_MISO      | U5 pin 2 (DO)    | SHORT    | SPI_MISO   |
| U3 SPI_CS        | U5 pin 1 (CS)    | SHORT    | SPI_CS     |
| Y1 pin 1         | U3 XI            | SHORT    | XI         |
| Y1 pin 2         | U3 XO            | SHORT    | XO         |

## Pass Criteria

- **All short circuit checks:** OPEN (no beep)
- **All ground checks:** < 1Ω
- **All power rail checks:** < 2Ω
- **All signal checks:** < 5Ω

Only proceed to power-on if ALL checks pass.

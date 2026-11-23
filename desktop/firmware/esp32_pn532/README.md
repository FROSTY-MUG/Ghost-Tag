# ESP32 + PN532 SPI Firmware for Ghost Bridge

This directory contains the verified, bounded serial firmware that enables Ghost Bridge to interact with physical NFC Forum Type 2 tags via an ESP32 microcontroller and a PN532 NFC module connected over hardware SPI.

---

## Hardware Architecture

```
Windows PC (Ghost Bridge)
       │
       │  USB Serial CDC (115200 baud, line-delimited JSON)
       ▼
ESP32 Development Board
       │
       │  Hardware SPI (SCK=18, MISO=19, MOSI=23, SS=5)
       ▼
PN532 NFC Module (configured in SPI mode via DIP switches)
       │
       │  13.56 MHz RF Field (ISO/IEC 14443-3A)
       ▼
Physical NFC Tag (NTAG213 / NTAG215 / NTAG216)
```

---

## Mandatory Pre-Wiring Checklist

Before connecting any wires or applying power, complete the following pre-flight verification:

1. **Identify Module**: Identify the exact PN532 module model, manufacturer, and board revision.
2. **Photograph Module**: Photograph the front and back of the module clearly showing all silkscreen labels and components.
3. **Identify VCC Voltage**: Identify the exact supported VCC input voltage range from manufacturer documentation.
4. **Identify Logic Level**: Identify whether the signal pins are 3.3 V-only or 5 V tolerant.
   > [!CAUTION]
   > **Voltage Safety**: Use only the VCC voltage explicitly supported by the exact PN532 module. ESP32 GPIO signals are 3.3 V logic. Do not connect 5 V logic to a 3.3 V-only PN532 input. A module regulator does not automatically prove that signal pins are 5 V tolerant.
5. **Identify Mode Switches**: Identify the exact SPI mode-switch configuration from board documentation.
   > [!IMPORTANT]
   > **Mode-Switch Setting**: Set the PN532 mode switches according to the exact module silkscreen and manufacturer documentation. Photograph the selected switch positions before applying power. Always power-cycle the board after changing mode switches.
6. **Confirm Pin Labels**: Confirm the PN532 SPI pin labels: SCK, MISO, MOSI, SS/CS.
7. **Confirm Extra Lines**: Confirm whether IRQ or RESET lines are required by the selected library setup.
8. **Check Level Shifting**: Confirm whether a bidirectional level shifter is required for your specific module.
9. **Confirm ESP32 Pinout**: Confirm the ESP32 board exact model and available GPIO pin mapping.
10. **Hold Power**: **Do not power the circuit until all 9 prior checks pass.**

---

## Wiring Table (ESP32 to PN532 SPI)

> Connect only after completing the pre-wiring checklist above. Ensure logic level compatibility between ESP32 (3.3 V logic) and the PN532 module.

| PN532 Pin | ESP32 Pin | Function | Voltage / Logic Note |
| :--- | :--- | :--- | :--- |
| **VCC** | `3V3` or `5V` | Power supply | Use ONLY voltage explicitly rated for your module |
| **GND** | `GND` | Ground reference | Common ground mandatory |
| **SCK** | `GPIO 18` | SPI Clock | 3.3 V logic |
| **MISO** | `GPIO 19` | SPI Master In / Slave Out | 3.3 V logic |
| **MOSI** | `GPIO 23` | SPI Master Out / Slave In | 3.3 V logic |
| **SS / CS** | `GPIO 5` | SPI Chip Select | 3.3 V logic |

---

## Read-Back Verification Specification

Read-back verification must compare the exact NDEF message bytes read from the physical tag with the exact NDEF message bytes requested by Ghost Bridge.

A SHA-256 comparison may be used as an additional integrity check, but it must not replace an exact byte-for-byte comparison.

The firmware response must include:
- Exact number of bytes written (`bytes_written`).
- Exact number of bytes read back (`bytes_read_back`).
- Whether the byte-for-byte comparison passed (`byte_comparison_passed: true`).
- A non-sensitive error code if verification failed (`ERROR_VERIFY_MISMATCH` or `ERROR_TAG_LOST`).

**Do not report `verified: true` unless the exact read-back comparison passes.**

---

## Dependencies & Tooling

To compile and upload this firmware:
1. **Arduino IDE 2.x** or **PlatformIO**.
2. **ESP32 Board Package**: Install via Arduino Boards Manager (`esp32` by Espressif Systems).
3. **Required Arduino Libraries**:
   - `Adafruit_PN532` by Adafruit (v1.3.0 or higher)
   - `ArduinoJson` by Benoit Blanchon (v6.21.0 or v7.x)

---

## Build & Flash Instructions

1. Connect the ESP32 to your Windows PC via a data-capable micro-USB / USB-C cable.
2. Open `ghost_pn532_firmware.ino` in Arduino IDE.
3. Select board: **ESP32 Dev Module**.
4. Select the detected COM port (e.g., `COM3`, `COM4`).
5. Click **Upload**.
6. Open Serial Monitor at **115200 baud** to confirm initialization:
   Sending `{"cmd": "HELLO"}` will respond with:
   `{"id":"","status":"OK","version":"1.0.0","protocol":"ghost-pn532-v1","hardware":"ESP32-PN532-SPI"}`

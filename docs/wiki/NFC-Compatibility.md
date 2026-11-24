# NFC Hardware Compatibility (`v2.1.0`)

## Supported NFC Forum Type 2 Tags (`ISO 14443-3A`)

| Chip Family | Total / User EEPROM | v1 Single-Tag (`54B` overhead) | v2 Bulk (`134B` overhead) | Support Notes |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | `180B` / `144B` | Yes (`52B` / `56B`) | **No (`0B`, `fits: false`)** | Fits short v1 secrets only; NDEF framing + 134B v2 overhead exceeds 144B user EEPROM. |
| **NTAG215** | `540B` / `504B` | Yes (`404B` / `411B`) | Yes (`326B` / `333B`) | Recommended standard chip for v1 and v2 distributed vaults. |
| **NTAG216** | `924B` / `888B` | Yes (`784B` / `795B`) | Yes (`706B` / `717B`) | Largest Type 2 chip; minimizes tag count in multi-tag bulk vaults. |
| **MIFARE Classic** | Proprietary | Rejected | Rejected | Unsupported non-Type-2 protocol and legacy Crypto-1 cipher. |
| **MIFARE Ultralight (64B)** | `64B` total | Rejected | Rejected | Insufficient EEPROM capacity (`< 54B` v1 / `< 134B` v2 overhead). |

> Physical NFC tag testing against real Android NFC handsets, ACS ACR122U USB readers, and ESP32+PN532 hardware remains pending final hardware verification (`../../PROJECT-STATUS.md`).

# Ghost-Tag NFC Tag Hardware Matrix & Memory Layout

Ghost-Tag deliberately restricts its hardware target to **NFC Forum Type 2** tags (NXP NTAG21x and MIFARE Ultralight family) to provide reliable, standard-compliant NDEF operations without proprietary protocol vulnerabilities.

---

## 1. Supported Tag Families & Capacities

| Tag Hardware Family | Total Memory | User Memory Pages | Usable NDEF Space | Max Ghost-Tag Plaintext |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | 180 Bytes | Pages 4 .. 39 (144 Bytes) | 137 Bytes | **45 Bytes** |
| **NTAG215** | 540 Bytes | Pages 4 .. 129 (504 Bytes) | 496 Bytes | **404 Bytes** |
| **NTAG216** | 924 Bytes | Pages 4 .. 225 (888 Bytes) | 872 Bytes | **780 Bytes** |
| **MIFARE Ultralight** | 64 Bytes | Pages 4 .. 15 (48 Bytes) | 48 Bytes | *Too small (< 54B overhead)* |
| **MIFARE Ultralight C**| 192 Bytes | Pages 4 .. 39 (144 Bytes) | 137 Bytes | **45 Bytes** |
| **MIFARE Ultralight EV1 (MF0UL11)** | 80 Bytes | Pages 4 .. 15 (48 Bytes) | 48 Bytes | *Too small (< 54B overhead)* |
| **MIFARE Ultralight EV1 (MF0UL21)** | 164 Bytes | Pages 4 .. 33 (120 Bytes) | 113 Bytes | **21 Bytes** |

> [!NOTE]
> For general use, **NTAG215** (~404 bytes plaintext) and **NTAG216** (~780 bytes plaintext) are strongly recommended for secrets, recovery phrases, credentials, and configuration profiles.

---

## 2. Type 2 Tag Memory Map & Safe Page Addressing

Type 2 tags structure memory into 4-byte pages. Ghost-Tag enforces strict page addressing bounds:

```
Page Index   Size       Description                  Ghost-Tag Access Rule
--------------------------------------------------------------------------------------------------
Page 0       4 Bytes    UID0..UID2, Manufacturer     READ-ONLY (Hardware write protected)
Page 1       4 Bytes    UID3..UID6                   READ-ONLY (Hardware write protected)
Page 2       4 Bytes    Internal / Static Lock Bits  READ-ONLY (Never overwrite to prevent bricking)
Page 3       4 Bytes    Capability Container (CC)    READ-ONLY / PRESERVE (Defines NDEF size)
--------------------------------------------------------------------------------------------------
Page 4       4 Bytes    Start of User Memory         WRITABLE (Start of NDEF data area)
...          4 Bytes    User Data Pages              WRITABLE (Envelope payloads and sanitization)
Page N       4 Bytes    End of User Memory           WRITABLE (Family-specific upper boundary)
--------------------------------------------------------------------------------------------------
Page N+1 ..  4 Bytes    Dynamic Lock & Config Pages  FORBIDDEN (Never touch during write or wipe)
```

### Safety Rules:
1. **Capability Container Protection**: Page 3 (`CC`) is never included in user data write or destructive wipe sweeps.
2. **Lock Bit Preservation**: Ghost-Tag never sets OTP or permanent dynamic lock bits without explicit user request.
3. **Destructive Overwrite Exclusions**: Wiping operates strictly within `[Page 4, Page N]`, ensuring tags remain re-writable.

---

## 3. Unsupported Hardware Architectures

The following tag types are explicitly rejected upon detection with `TAG_UNSUPPORTED`:

- **MIFARE Classic 1K / 4K**: Proprietary Crypto-1 cipher with known cryptographic breaks; non-compliant with standard Android NDEF API across all chipsets.
- **MIFARE DESFire**: Complex multi-application file system requiring proprietary APDU authentication routines.
- **Sony FeliCa (NFC Forum Type 3)**: Distinct RF framing and framing commands outside the Type 2 scope.
- **ISO 15693 (NFC-V / Vicinity Cards)**: Long-range industrial tags with differing timing and memory boundaries.
- **Card Emulation Modes**: Emulated cards are rejected to prevent replay and relay ambiguities.

---
name: NFC Hardware & Chip Compatibility Report
about: Report compatibility or read/write behavior with specific NFC tags or mobile chipsets
title: '[NFC-COMPAT]: '
labels: ['nfc-compat', 'hardware']
assignees: 'FROSTY-MUG'
---

## NFC Hardware & Chip Details
- **NFC Tag Type / IC**: [e.g. NTAG213, NTAG215, NTAG216, MIFARE Ultralight EV1, ST25TV]
- **Advertised Physical Capacity**: [e.g. 144 bytes, 504 bytes, 888 bytes]
- **Device Model & Manufacturer**: [e.g. Google Pixel 8, Samsung Galaxy S23, OnePlus 11]
- **Client Used**: [ ] Android APK (`v2.1.0` staging / `v2.0.6`)  [ ] Web Client (Chrome on Android)  [ ] Desktop Ghost Bridge (ACR122U / PN532)
- **Android OS Version**: [e.g. Android 14, Android 13]

## Observed Behavior
- **Automatic Chip Detection**: [ ] Successful  [ ] Failed  [ ] Incorrect capacity reported
- **Write Verification**: [ ] Passed  [ ] Read-back mismatch  [ ] Tag locked / Read-only error
- **Bulk Vault Interoperability**: [ ] Supported  [ ] Missing chunks / Incomplete

## Steps to Reproduce
1. Tap NFC tag on device transceiver.
2. Observe capacity readout and detected tag type.
3. Attempt single-tag or bulk-vault write.
4. Attempt read-back decryption.

## Log Output or Screenshot
```
[Paste relevant adb logcat or browser console logs here]
```

## Additional Notes
[Any additional context on tag antenna size, shielding, or metal interference]

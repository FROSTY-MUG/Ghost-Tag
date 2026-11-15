# Troubleshooting & Common Issues

Solutions to common hardware, browser, and operational questions in Ghost-Tag.

---

## 1. NFC Hardware & Scanning Issues

### Tag Not Detected
- **Antenna Location**: NFC antennas on modern phones are located near the top rear camera module or in the center rear. Slowly glide the tag along the upper half of your phone's back.
- **Thick Phone Cases**: Heavy metal cases or wallet folios with RFID blocking can prevent RF coupling. Remove thick cases when writing high-density data.
- **NFC Disabled**: Check that NFC is toggled ON in Android Settings (`Connected devices` → `NFC`).

### Write Failed or Write Could Not Be Verified
- **Tag Removed Too Quickly**: Ghost-Tag performs a two-step write and read-back verification. Keep the tag firmly pressed against the phone until you see the confirmation checkmark or vibrate prompt.
- **Locked or Read-Only Tags**: If a tag was previously locked with static lock bytes (e.g. amiibo or commercial tags), Ghost-Tag cannot write to it. Use fresh, unlocked NTAG213/215/216 chips.

---

## 2. Web Client Issues

### "This browser does not support Web NFC"
- Web NFC is currently implemented in **Google Chrome for Android**.
- Web NFC is **not supported** on iOS Safari or desktop Chrome (unless desktop emulation mode is active).
- Ensure the site is loaded over HTTPS (`https://frosty-mug.github.io/Ghost-Tag/`). Web NFC is disabled on plain HTTP.

### "NFC Permission Denied"
- In Chrome on Android, tap the lock/settings icon in the address bar → **Permissions** → **NFC** → Set to **Allow**.

---

## 3. Decryption Issues

### "More Tags Needed"
- Ghost-Tag tells you exactly how many chunks are collected versus total required (e.g. `Collected: 5 / 12 chunks`).
- Scan the remaining NFC tags belonging to this vault. Tags can be scanned in any order.

### "Passphrase is Incorrect"
- Verify that caps lock is not enabled and that you are entering the same passphrase used to encrypt this specific vault.
- If you used a different Ghost account to encrypt the tags, restore that account using its original 12-word recovery phrase.

### "Cannot delete entry: required tag is missing"
- On Android, deleting an individual entry requires safely rewriting the affected NFC tags. If any tag is missing or damaged, the deletion is aborted to prevent permanent corruption of remaining files.

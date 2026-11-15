# Recovery & Account Portability

Ghost-Tag's recovery architecture ensures you can regain access to your encrypted NFC tags even if your phone is lost, broken, or wiped.

---

## 1. What You Need for Recovery

To recover your Ghost-Tag system on a replacement device, you need:
1. Your **12-word BIP-39 recovery phrase** (saved offline during account setup).
2. Your **master passphrase** (used to unlock the vault and decrypt tags).
3. Your physical **NFC tags**.

---

## 2. Step-by-Step Restoration Flow

1. Install the Ghost-Tag APK on your new Android device, or open the web client on Chrome:
   [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)
2. On the welcome screen, select:
   `[ I Already Have a Recovery Phrase ]`
3. Enter your 12 words separated by spaces.
4. Ghost-Tag validates the BIP-39 checksum:
   - If a word is misspelled or out of order, you receive an immediate syntax warning.
5. Ghost-Tag computes:
   `account_id = KDF(recovery_phrase, "ghost-account-id")`
6. The app connects anonymously to Supabase to retrieve your encrypted vault configuration.
7. Enter your master passphrase to unwrap your keys locally.
8. Account restored! You can now scan and decrypt your physical NFC tags.

---

## 3. What If You Lose Your Passphrase?

> **WARNING**: Ghost-Tag is built on zero-knowledge encryption. There is no "Forgot Passphrase" link, no customer service reset, and no backdoor. If you lose both your recovery phrase and your passphrase, your encrypted data cannot be decrypted by anyone.

# Creating an Account

Account creation is mandatory before encrypting or decrypting in Ghost-Tag.

---

## 1. Principles of Ghost Accounts

- **Local-First**: Accounts are initialized in the browser or on the device without pinging a central server or identity provider.
- **Anonymous**: No email, username, phone number, or KYC verification is required or accepted.
- **Portable**: Your account identity is completely defined by your **12-word recovery phrase**. You can restore your identity onto any device at any time.

---

## 2. Account Creation Flow

### Step 1: Welcome Screen
When you launch Ghost-Tag for the first time, you are presented with:
```text
Welcome to Ghost
Create your anonymous Ghost account.
Your recovery phrase is your identity.
Your passphrase protects your encrypted data.
[Create Account]  [I Already Have a Recovery Phrase]
```

### Step 2: Master Passphrase
You are prompted to enter a master passphrase:
- Must be at least **16 characters long**.
- Never stored on disk or sent over the network.
- Never logged or copied to the clipboard.
- Used to derive the Key Encryption Key (KEK) via PBKDF2 (Web) or Argon2id (Android).

### Step 3: 12-Word Recovery Phrase Generation
Ghost-Tag generates a standard 12-word BIP-39 English phrase from 128 bits of high-entropy randomness generated via `crypto.getRandomValues()`.
- You must write these words down offline on paper or metal.
- Never take a screenshot or store them in cloud notes.

### Step 4: Word Confirmation
Ghost-Tag randomly challenges you to confirm three word positions (e.g. Word 4, Word 8, Word 11) to ensure you have saved the phrase accurately.

### Step 5: Anonymous Cloud Sync Setup
Once confirmed:
- Ghost-Tag computes a deterministic UUIDv4:
  `account_id = KDF(recovery_phrase, "ghost-account-id")`
- Automatically signs into Supabase anonymously (`signInAnonymously()`).
- Enables cross-device recovery of encrypted vault metadata without storing any secrets in the cloud.

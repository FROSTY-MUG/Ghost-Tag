# Ghost-Tag v2.0.5 — Full Product Specification & System Manual

> [!NOTE]
> **DOCUMENT STATUS: HISTORICAL SPECIFICATION & SYSTEM MANUAL**  
> This system manual defines the original v2.0.5 release architecture. For the active, canonical technical specification covering the current v2.1.0 codebase and cross-platform zero-knowledge recovery protocol, refer to [CANONICAL-SPECIFICATION.md](./CANONICAL-SPECIFICATION.md).

## Core Rule & Fallback Contract
Ghost-Tag can be designed as a cross-platform encrypted NFC vault, but you must separate three things: the Android APK, the web app, and iOS. They can share the same encrypted NFC format, but they cannot all have the same NFC permissions or capabilities.

The realistic cross-platform rule is:
A tag written by the Android APK can be read by the web app or iOS app only if that platform supports NDEF reading, the user has the correct passphrase/key material, and the tag has enough accessible NDEF data.

Web NFC in Chrome on Android supports NDEF reading and writing, requires HTTPS, and is limited to NDEF; it does not guarantee raw-tag access or support on every browser. iOS does not provide the same Web NFC API, so a website cannot reliably replace an iOS native app for NFC reading or writing.

---

## 1. Product Definition
Ghost-Tag lets a user create an anonymous encrypted account, scan NFC tags, add encrypted text/files/photos/videos/URLs, write the encrypted content across one or more NFC tags, and later decrypt it using the same passphrase.
The Android APK is the primary full client. The web app is the cross-platform companion client deployed on GitHub Pages.
A tag written by Android must be decryptable by the web app, and a tag written by the web app must be decryptable by Android, provided the user has the correct passphrase and scans the required tags.

---

## 2. Core Product Rules
Implement these rules exactly:
1. Account creation is mandatory before encryption or decryption.
2. Use one local-first Ghost account per browser profile or Android installation.
3. Use Supabase anonymous authentication.
4. Use a standard 12-word BIP-39 English recovery phrase.
5. The recovery phrase is the user’s portable account identity.
6. The passphrase protects and unlocks the encrypted vault.
7. Use one passphrase for both encryption and decryption.
8. Do not create an auto-generated decryption passphrase.
9. Encrypt everything by default.
10. Do not write readable public URLs.
11. Store only encrypted vault metadata in Supabase.
12. Do not implement a scanned-chunk cache.
13. Allow Android users to delete individual entries only through a safe full rewrite flow.
14. Show a corruption warning before deleting an entry.
15. Make every button functional.
16. Make every test pass.
17. Make the APK installable and fully working.
18. Deploy the web app to GitHub Pages.
19. Host the APK on GitHub Releases.

---

## 3. Visual Design

### 3.1 Design Language
- Pure black or near-black background (`#000000`, `#080808`, `#121212`).
- White or off-white text (`#ffffff`, `#e0e0e0`).
- Minimal gray borders (`#222222`, `#2a2a2a`).
- One subtle accent color (`#00ff66` or brutalist monochrome/accent).
- Large readable typography.
- Generous spacing.
- Very few buttons.
- Monospace only for NFC status and technical footer.
- No gradients, decorative illustrations, or generic AI art.

### 3.2 Ghost Hero Image
Source: `web/assets/ghost-hero.jpg` copied to `web/public/assets/ghost-hero.jpg` and `web/src/assets/ghost-hero.jpg`.
Usage:
- In the initial loading screen.
- As a subtle background element.
- With approximately 230% blur or equivalent heavy blur (e.g. 48px blur).
- At low opacity (~10%).
- Behind the Ghost logo.
- With a dark overlay for readability.
- Do not use it as a sharp foreground illustration.

### 3.3 Ghost Logo
Custom brutalist ghost logo:
- Minimal geometric ghost silhouette.
- Two clean negative-space eyes.
- Sharp, modern, abstract.
- Monochrome.
- Works at 16 px favicon size and large hero size.
- No cute cartoon ghost.
- No glow.
- No complicated details.
- Do not use a stock ghost icon.

### 3.4 Landing Page
```text
GHOST [custom ghost logo] Encrypted NFC storage. [ Launch Web Version ] [ Download Android APK ] Technical · Security · Privacy · Source
```
Remove all other homepage content.

### 3.5 Footer
All four footer links must open the same page:
`/technical`
Show all four sections on that page:
`Technical` `Security` `Privacy` `Source`
Use anchors:
`/technical#technical` `/technical#security` `/technical#privacy` `/technical#source`
The user must be able to read all four sections from that same page.

### 3.6 Buttons
Every button must respond:
- Hover state
- Active state
- Focus-visible state
- Disabled state
- Loading state
- Success state
- Error state
- Keyboard accessibility
- Mobile touch feedback

Required buttons:
```text
Launch Web Version
Download Android APK
Create Account
Continue
Confirm
Start Scanning
End Scanning Process
All Chips Scanned
Add Text
Add File
Add Photo
Add Video
Add URL
Save Entry
Add Another Entry
Write Everything
Encrypt and Write
Stop Writing
Decrypt Now
View
Download
Clear Temporary Data
Restore Account
Delete Entry
```

---

## 4. Account Model

### 4.1 Account Creation
Account creation is mandatory before a user can encrypt or decrypt.
```text
Welcome to Ghost
Create your anonymous Ghost account.
Your recovery phrase is your identity.
Your passphrase protects your encrypted data.
[Create Account]  [I Already Have a Recovery Phrase]
```

### 4.2 Create Passphrase
```text
Create passphrase
This protects your Ghost vault.
[________________________________]
Minimum 16 characters.
[Continue]
```
Rules:
- Minimum 16 characters.
- Never store the passphrase.
- Never send it to Supabase.
- Never store it in localStorage.
- Never log it.
- Never copy it to clipboard.
- Use it for both encryption and decryption.

### 4.3 Generate Recovery Phrase
Generate a standard 12-word BIP-39 English recovery phrase.
Display:
```text
Your recovery phrase
Write these 12 words down offline.
1. word 2. word 3. word ... 12. word
This phrase restores your Ghost account on another device.
It is compatible with standard BIP-39 tooling.
Do not share it with anyone.
If you lose this phrase and your passphrase, you cannot recover your encrypted NFC data.
[I Have Saved It Safely]
```
BIP-39 uses a 128-bit entropy value and a 4-bit checksum for a 12-word mnemonic; each word maps to an 11-bit index in the 2,048-word English list.

### 4.4 Confirm Recovery Phrase
Ask the user to enter three random word positions:
```text
Confirm your recovery phrase
Enter word 4: [________]
Enter word 8: [________]
Enter word 11: [________]
[Confirm]
```

### 4.5 Account Created
```text
Account created.
Your Ghost account is ready.
[Encrypt]  [Decrypt]
```

---

## 5. Supabase Cloud Sync

### 5.1 Cloud Purpose
Supabase stores only an encrypted vault metadata blob.
It enables cross-device account recovery. It does not store plaintext, keys, recovery phrases, NFC contents, files, or scanned chunks.

### 5.2 Account Identity
Derive a stable account ID from the BIP-39 recovery phrase:
```text
account_id = KDF(recovery_phrase, "ghost-account-id")
```
Use a documented KDF and domain-separated derivation. Do not use the recovery phrase directly as an account ID.

### 5.3 Supabase Authentication
Use Supabase anonymous authentication.
Flow:
1. Generate 12-word BIP-39 recovery phrase.
2. Derive account ID from recovery phrase.
3. Create Supabase anonymous user (`supabase.auth.signInAnonymously()`).
4. Generate local vault keys.
5. Encrypt vault metadata locally.
6. Upload only encrypted vault metadata.
7. Store recovery phrase only in user’s offline backup.

### 5.4 Account Restoration
```text
Restore Ghost Account
Enter your 12-word recovery phrase.
[________________________________]
[Restore Account]
```
Flow:
1. User enters recovery phrase.
2. App validates BIP-39 checksum.
3. App derives the same account ID.
4. App authenticates to Supabase.
5. App downloads encrypted vault metadata.
6. App asks for passphrase.
7. App derives KEK locally.
8. App decrypts vault metadata locally.
9. Account restored.

### 5.5 Supabase Schema
```sql
create table ghost_vaults (
  account_id uuid primary key,
  user_id uuid not null,
  encrypted_vault_blob bytea not null,
  vault_version integer not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table ghost_vaults enable row level security;

create policy "owner_read_write" on ghost_vaults
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
```

### 5.6 Cloud Privacy
The cloud must never store:
- passphrase
- recovery phrase
- KEK
- DEK
- plaintext files
- plaintext NFC contents
- scanned chunks
- location data
- analytics

The cloud may store only:
- encrypted vault metadata
- encrypted key-wrapping material
- encrypted manifest
- account ID
- vault version
- timestamps

---

## 6. Vault Metadata
The encrypted vault metadata contains:
- `vault_version`
- `account_id`
- `created_at`
- `updated_at`
- `wrapped_dek`
- `recovery_envelope`
- `kdf_parameters`
- `salt`
- `file_manifests`
- `entry_metadata`
- `key_ids`
- `key_statuses`

It must never contain:
- passphrase
- recovery phrase
- KEK
- DEK
- plaintext entries
- plaintext files
- plaintext URLs
- plaintext NFC contents

---

## 7. Main Navigation
After account creation or restoration, show only:
```text
[ Encrypt ]  [ Decrypt ]
```
Secondary navigation:
```text
Account  Recovery  Settings
```
Remove from primary navigation:
- Interactive Workspace
- Web NFC
- Single Tag Vault
- Bulk File Vault
- Reconstruction
- Security and Anti-Tamper Matrix
- Technical Specifications
- Architecture
- Cryptography
- Security Hardening
- Binary Envelopes

---

## 8. Encrypt Flow

### 8.1 Start Encryption
```text
ENCRYPT
Scan the NFC tags you want to use.
[Start Scanning]
```

### 8.2 Scan Tags
User scans any number of NFC tags.
```text
TAGS SCANNED: 12
TAG 01 Type: Detected automatically Total storage: 504 bytes Writable storage: 496 bytes
TAG 02 Type: Detected automatically Total storage: 504 bytes Writable storage: 496 bytes
TOTAL READABLE STORAGE: 6,048 bytes
TOTAL WRITABLE STORAGE: 5,952 bytes
TOTAL USABLE GHOST STORAGE: 5,830 bytes
[End Scanning Process]
```
The user must be able to tap `[End Scanning Process]` at any time. Do not force the user to scan a fixed number of tags.

### 8.3 Add Entries
After scanning:
```text
SCANNING COMPLETE
Tags scanned: 12
Total readable storage: 6,048 bytes
Total writable storage: 5,952 bytes
Usable Ghost storage: 5,830 bytes
What would you like to store?
[Add Text] [Add File] [Add Photo] [Add Video] [Add URL]
```

### 8.4 Text Entry
```text
ADD TEXT
[________________________________]
[Save Entry]
```

### 8.5 File Entry
```text
ADD FILE
Select any file: text, image, video, PDF, ZIP, or other file.
[Choose File]
Selected: notes.txt  Size: 12 KB
[Save Entry]
```

### 8.6 Photo Entry
```text
ADD PHOTO
[Choose Photo]
Selected: photo.jpg  Size: 240 KB
[Save Entry]
```

### 8.7 Video Entry
```text
ADD VIDEO
[Choose Video]
Selected: video.mp4  Size: 3.1 MB
[Save Entry]
```

### 8.8 URL Entry
All URLs are encrypted by default:
```text
ADD URL
Enter a link: [________________________________]
Example: https://instagram.com/yourusername
This link will be encrypted. It will not open like a normal NFC link.
[Save Entry]
```
Do not offer a public-link mode in v2.0.5.

### 8.9 Entry List
After saving an entry:
```text
YOUR ENTRIES
1. Text — “Server recovery notes”
2. Photo — photo.jpg
3. Video — video.mp4
4. URL — https://instagram.com/yourusername
Total size: 3.35 MB
Usable Ghost storage: 5.83 KB
[Add Another Entry]  [Write Everything]
```

### 8.10 Capacity Check
If content exceeds capacity:
```text
NOT ENOUGH NFC STORAGE
Content size: 3.35 MB
Usable Ghost storage: 5.83 KB
Scan more NFC tags or remove entries.
[Scan More Tags]  [Remove Entry]
```
If content fits:
```text
CONTENT READY
Content size: 3.35 MB
Usable Ghost storage: 5.83 KB
Required tags: 32
Scanned tags: 40
Extra tags: 8
Only 32 tags are required. Please set aside the other 8 tags.
[Use 32 Tags]
```

### 8.11 Passphrase Prompt
```text
ENTER PASSPHRASE
Your entries will be encrypted and written across the selected NFC tags.
[________________________________]
[Encrypt and Write]
```

### 8.12 Write Everything
When tapped `[Write Everything]` or `[Encrypt and Write]`:
1. Encrypt all selected entries.
2. Package them into a versioned Ghost payload.
3. Split the encrypted payload into chunks.
4. Write one encrypted chunk per required NFC tag.
5. Read back every tag.
6. Verify every chunk.
7. Show progress.
8. Allow Stop at any time:
```text
ENCRYPTING...
SPLITTING INTO 32 CHUNKS...
WRITING CHUNK 1 / 32...
VERIFYING CHUNK 1 / 32...
WRITING CHUNK 2 / 32...
PROGRESS: 17 / 32  REMAINING TAGS: 15
[Stop Writing]
```

### 8.13 Completion
```text
ENCRYPTION COMPLETE
32 tags written and verified. 4 entries encrypted.
Keep these 32 tags together. You can scan them in any order later.
[Done]
```

---

## 9. Decrypt Flow

There must be one button:
```text
[ Decrypt Now ]
```

### 9.1 Decrypt Entry
```text
DECRYPT NOW
Scan the Ghost-Tag NFC tags you want to decrypt.
[Start Scanning]
```

### 9.2 Scan Tags
```text
TAGS SCANNED: 7
GHOST DATA FOUND: 5
UNKNOWN TAGS: 2
[All Chips Scanned]
```

### 9.3 Passphrase Prompt
```text
ENTER PASSPHRASE
Enter the passphrase used to encrypt these tags.
[________________________________]
[Decrypt]
```

### 9.4 Decryption
```text
IDENTIFYING VAULT...
VERIFYING CHUNKS...
RECONSTRUCTING DATA...
DECRYPTING...

DECRYPTION COMPLETE
Recovered entries:
1. Text — “Server recovery notes”
2. Photo — photo.jpg
3. Video — video.mp4
4. URL — https://instagram.com/yourusername
[View]  [Download]  [Clear Temporary Data]
```

### 9.5 Missing Chunks
```text
MORE TAGS NEEDED
Collected: 5 / 12 chunks
Missing: 7 chunks
Scan the remaining Ghost tags to decrypt the complete content.
[Scan More Tags]  [Cancel]
```

### 9.6 Wrong Passphrase
```text
DECRYPTION FAILED
The passphrase is incorrect or the data was encrypted with a different Ghost account.
[Try Again]
```

### 9.7 Tampered Data
```text
DATA TAMPERED OR INVALID
One or more scanned Ghost records failed integrity verification.
[Scan More Tags]  [Cancel]
```

---

## 10. Cross-Platform Flow

### 10.1 Android Writes, Web Decrypts
User A on Android APK -> Creates Ghost account -> Scans NFC tags -> Adds text, photo, video, URL -> Enters passphrase -> Encrypts and writes tags -> Gives tags to User B -> User B opens Ghost website on Android -> Creates Ghost account or restores account -> Chooses Decrypt -> Enters passphrase -> Scans all tags -> Taps All Chips Scanned -> Website decrypts and displays content.

### 10.2 Web Writes, Android Decrypts
User A on Ghost website -> Creates account -> Scans tags -> Adds content -> Enters passphrase -> Encrypts and writes tags -> User B opens Android APK -> Chooses Decrypt -> Enters passphrase -> Scans tags -> Taps All Chips Scanned -> Android decrypts and displays content.

### 10.3 Cross-Device Recovery
User creates account on Android -> Receives 12-word recovery phrase -> Changes Android device -> Installs Ghost-Tag on new device -> Chooses I Already Have a Recovery Phrase -> Enters 12 words -> Account restored -> User scans old NFC tags -> Old encrypted content becomes readable.

---

## 11. Shared Ghost Format
Android APK and web app must implement the exact same:
- NDEF MIME type: `application/vnd.ghost.bulk`
- Binary envelope (Little-Endian):
  `"GTAG" + format version (1B) + record type (1B) + vault ID (16B) + file ID (16B) + key ID (16B) + global chunk index (4B LE) + total vault chunks (4B LE) + file chunk index (4B LE) + total file chunks (4B LE) + ciphertext length (4B LE) + chunk hash (32B SHA-256) + AES-GCM nonce (12B) + encrypted chunk + AES-GCM authentication tag (16B)`
- Crypto:
  - AES-256-GCM.
  - 12-byte random nonce.
  - 16-byte authentication tag.
  - SHA-256 for ciphertext integrity hashes.
  - PBKDF2 (Web) / Argon2id (Android) key derivation.
  - 256-bit DEK.
  - Versioned key wrapping.
  - Versioned recovery envelope.

---

## 12. NFC Behavior

### 12.1 Automatic Detection
Do not show chip selectors (`NTAG213`, `NTAG215`, `NTAG216`).
Detect the tag automatically:
```text
Tag detected.
Total storage: 504 bytes
Writable storage: 496 bytes
```

### 12.2 Stop Controls
During encryption: `[End Scanning Process]`
During decryption: `[All Chips Scanned]`
Both must:
- Stop the NFC session.
- Preserve already scanned tags.
- Cancel pending NFC operations.
- Allow user to continue.
- Not corrupt partially written data.

### 12.3 Write Verification
Never mark a write successful until:
write encrypted NDEF record -> read tag back -> parse Ghost envelope -> verify AES-GCM authentication tag -> verify ciphertext hash -> WRITE VERIFIED.

---

## 13. Delete Individual Entry (Android Only)

### 13.1 Delete Warning
```text
DELETE ENTRY
Entry: photo.jpg
Deleting this entry requires rewriting encrypted Ghost data on the affected NFC tags.
This operation may fail if a tag is damaged, removed too early, or becomes unreadable.
Existing entries may become temporarily unavailable until the rewrite completes.
[CANCEL]  [DELETE ENTRY]
```

### 13.2 Delete Flow
1. Decrypt local vault manifest.
2. Remove selected entry.
3. Re-encrypt remaining content.
4. Recalculate chunk count and hashes.
5. Identify affected NFC tags.
6. Ask user to scan required tags.
7. Rewrite affected tags.
8. Read back and verify every rewritten tag.
9. Mark deletion complete only after verification.

If a required tag is missing:
```text
CANNOT DELETE ENTRY
The NFC tag containing required encrypted data is missing or unreadable.
The entry cannot be safely deleted.
```

---

## 14. iOS Handling
For v2.0.5:
```text
iOS is not supported yet. An iOS app will be available later.
```
Do not show an iOS download button.
If an iPhone user opens the site:
```text
iOS is not supported yet.
Ghost-Tag NFC scanning and writing require the future Ghost-Tag iOS app.
You can still recover a vault or download files if you have an encrypted Ghost backup.
[Continue Without NFC]
```

---

## 15. Error Messages
Use simple messages:
- `NFC is not available on this device.`
- `This browser does not support Web NFC.`
- `Tag detected, but it is not writable.`
- `This tag does not have enough space.`
- `This tag already contains Ghost data.`
- `This tag contains unknown data.`
- `Write failed. Please try again.`
- `Write could not be verified.`
- `Passphrase is incorrect.`
- `Data was modified or is invalid.`
- `More tags are needed.`
- `Recovery phrase is invalid.`
- `Cloud backup is unavailable.`
- `iOS is not supported yet.`
- `Cannot delete entry: required tag is missing.`

---

## 16. Technical Page (`/technical`)
A single consolidated page `/technical` (and `technical.html` for static GitHub Pages) with anchors:
- `#technical`
- `#security`
- `#privacy`
- `#source`
The user must be able to read all four sections on that same page.
Footer links point to `/technical#technical`, `/technical#security`, `/technical#privacy`, `/technical#source`.

---

## 17. Scanned-Chunk Cache Elimination
Per explicit rule:
"Do not implement a scanned-chunk cache."
"No scanned-chunk cache exists."
All scanned tags and chunks exist purely in volatile session memory during an active operation and are completely cleared on completion or session reset.

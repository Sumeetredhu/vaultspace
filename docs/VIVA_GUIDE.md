# VaultSpace: Viva Guide

How the app works, why each decision was made, and where it is in the code. Read it top to bottom once, then use sections 9 and 10 to revise.

---

## 1. The two-minute pitch

VaultSpace is an Android app for storing and sharing sensitive documents such as Aadhaar, marksheets and bank statements.

- **Files are encrypted on the phone before upload.** The server only ever stores random-looking bytes. Even the file *names* are encrypted.
- **Sharing is end-to-end.** The owner's phone encrypts the file's key for the recipient's public key, so only the recipient's phone can open it.
- **The owner's rules are enforced by the server on every request:** expiry, open limit, view-only, optional passphrase, and instant revoke. A modified app cannot bypass them.
- **Usable security, straight from the Phase 1 findings:**
  - one merged share screen with a plain-English summary
  - labelled navigation
  - recovery key for forgotten passwords
  - fingerprint unlock
  - honest notices ("downloaded copies can't be removed")
- **About 4,900 lines, all our own, and zero libraries.** The server uses only Node.js built-ins. The app uses only the Android framework: no AndroidX, no Compose, no Retrofit, no Firebase.

---

## 2. Architecture

```
 Android app (Kotlin)                           Server (Node.js, built-ins only)
 ┌────────────────────────────┐   HTTPS +      ┌──────────────────────────────┐
 │ Screens (Ui.kt DSL)        │   pinned cert  │ http.js   router, limits,    │
 │ Crypto.kt  all crypto      │ ─────────────► │           validation, headers│
 │ Data.kt    vault, sharing  │                │ auth.js   accounts, sessions │
 │ Api.kt     HTTPS client    │                │ files.js  encrypted chunks   │
 │ DeviceUnlock.kt  Keystore  │                │ shares.js rule enforcement   │
 └────────────────────────────┘                │ db.js     SQLite + hash chain│
   keys live only in memory                    └──────┬───────────────┬───────┘
                                                      │               │
                                              vaultspace.db     blobs/<file>/<ver>/<chunk>
                                              (only hashes and  (only ciphertext)
                                               wrapped keys)
```

- **Why Android instead of a website?** Android lets us block screenshots (`FLAG_SECURE`), keep keys in secure hardware (Android Keystore + biometrics), and pin the server certificate. A browser can't do any of these, and a native app also removes the whole XSS/CSRF class of bugs.
- **Why a server at all?** Someone has to enforce expiry, open limits and revocation. It can't be the sender's phone (it may be offline) or the recipient's phone (they control it). So it's a server that neither of them controls.

---

## 3. The key hierarchy (the heart of the viva)

```
password ──PBKDF2-SHA256, 600,000 rounds, random 16-byte salt──► master (32 bytes)
master ──HKDF "vs-auth"──► authKey   sent to the server, which stores scrypt(authKey) only
master ──HKDF "vs-kek" ──► KEK       never leaves the phone

KEK          encrypts ─► VaultKey     (random 32 bytes, one per account, never changes)
RecoveryKey  encrypts ─► VaultKey     (second copy, for "forgot password")
VaultKey     encrypts ─► each FileKey, the user's EC private key, a copy of the recovery key
FileKey      encrypts ─► the file (1 MiB chunks) and its metadata (name, type, category, size)
Recipient's public key (ECIES) encrypts ─► FileKey, for one share
Optional passphrase key encrypts ─► that wrapped FileKey again
```

**In plain words:**

- **Password → two different keys.** We stretch the password with PBKDF2, which is deliberately slow so guessing is expensive. HKDF then splits the result into two unrelated keys. The **authKey** proves to the server that you know the password. The **KEK** (key-encryption key) unlocks your vault. Because the server only ever sees the authKey, it can never derive the KEK.
- **VaultKey.** A random master key for your files. The password only *wraps* it. So changing the password just re-wraps one 32-byte key; no file needs re-encrypting.
- **FileKey.** A new random key for every file. Deleting a file deletes its wrapped key, so leftover ciphertext can never be decrypted. This is called *crypto-shredding*.
- **Recovery key.** 20 random bytes (160 bits), shown as 32 characters such as `9ZWD A007 0FHE PWKA …`. It wraps a second copy of the VaultKey, so a forgotten password does not mean lost files. In Phase 1 the example was `apple-vinegar-67901`, about 40 bits, which could be brute-forced, so we changed it.

**The "aad" labels** (additional authenticated data). Every encryption is tagged with what it is and where it belongs: `vs-vault`, `vs-fkey|<fileId>`, `vs-chunk|<fileId>|<version>|<index>|<isLast>` and so on. AES-GCM refuses to decrypt if the label doesn't match. So a malicious server cannot:
- swap chunk 2 with chunk 3
- move a chunk to another file
- cut a file short (the last chunk must carry `isLast=1`)
- present one encrypted key as another

**Where:** `android/.../Crypto.kt` (`passwordKeys`, `seal`, `open`, `hkdf`, `wrapFor`, `unwrapFrom`) and `Data.kt` (`Vault.encryptChunks`, `Vault.decryptChunks`, `Meta`).

---

## 4. Crypto building blocks, explained simply

| Primitive | What it does | Where we use it | Why this one |
|---|---|---|---|
| **AES-256-GCM** | Encrypts *and* detects tampering (16-byte tag) | Every encryption in the app; TOTP secrets on the server | Authenticated encryption, built into Android and Node |
| **Random 96-bit nonce** | Makes each encryption unique | Fresh for every `seal()` | Reusing a nonce with the same key breaks GCM; random 96-bit values are safe at our volume |
| **PBKDF2-HMAC-SHA256** | Slow, salted password stretching | Password (600k rounds), share passphrase (200k) | OWASP 2023 recommendation. Argon2 isn't built into Android, and writing it ourselves would be riskier |
| **HKDF-SHA256** (RFC 5869) | Turns one secret into several independent keys | authKey/KEK split, recovery keys, ECIES | Standard. We wrote it in two lines on top of HMAC |
| **ECDH P-256 → ECIES** | Two key pairs agree on a shared secret | Encrypting a FileKey for a recipient | Asymmetric: the sender needs only the recipient's public key |
| **scrypt** (server) | Memory-hard hash | Stores authKey, recovery proof, passphrase proof | A stolen database gives no usable login secret |
| **SHA-256** | One-way hash | Session tokens, device tokens, history chain | Fast; inputs are already random, so stretching isn't needed |
| **HMAC-SHA256** (server secret) | Keyed hash | Email codes at rest, fake salts | Forging one needs the server secret |
| **TOTP** (RFC 6238) | 6-digit code changing every 30 s | Optional two-factor login | Works with Google/Microsoft Authenticator. Ours is about 10 lines |

> **"Did you write your own crypto?"** No. The primitives (AES, SHA, PBKDF2, ECDH) come from the platform: Android's `javax.crypto` and Node's `crypto` module. Hand-written AES would be the easiest way to create a real vulnerability. Everything built *on top* of them is our own original code: the key hierarchy, the chunk format, HKDF, ECIES, TOTP, the recovery-key encoding and the hash chain.

---

## 5. Every flow, step by step

### 5.1 Sign up (`SignupScreen` → `POST /auth/signup/start`, `/auth/signup/finish`)
1. The user enters their name, email and password. The phone checks the password itself, because the server never sees it. The rules are in `PasswordCheck`:
   - at least 12 characters
   - not a common password
   - doesn't contain the email name
   - no long repeated characters
2. `signup/start` emails a 6-digit code.
   - The server responds identically whether or not the email already exists.
   - If it exists, the real owner gets a "someone tried to sign up with your email" message instead. This prevents *account enumeration*.
3. The user enters the code. The phone then creates **every key locally**: salt, password keys, VaultKey, recovery key, and an EC P-256 key pair. It sends only the authKey and *wrapped* keys to `signup/finish`.
4. The server checks the code (single use, 5 tries, 10 minutes) **before** creating the account. Verifying the email matters: otherwise someone could register `rahul@gmail.com` first and receive files meant for Rahul.
5. The recovery key screen requires a tick box *and* typing the last 4 characters, so the user really saves it.

### 5.2 Log in (`LoginScreen.login` → `/auth/prelogin`, `/auth/login`)
1. `prelogin` returns the user's salt.
   - For unknown emails it returns a **fake but stable** salt, `HMAC(serverSecret, email)`, so attackers can't tell which emails have accounts.
2. The phone runs PBKDF2 and sends the authKey. The server compares `scrypt(authKey)` in constant time.
   - It runs scrypt even for unknown users, so response timing reveals nothing.
3. Wrong guesses are slowed down after 5 failures (30 s, 1 min, 2 min … up to 15 min).
   - There is never a permanent lock, because that would let an attacker lock *you* out.
4. If two-factor is on, the server answers `need2fa` and the app asks for the 6-digit code.
5. On success, the server returns a session token plus the wrapped VaultKey and private key. The phone unwraps them with the KEK. A "new login" alert is recorded and emailed.

### 5.3 Fingerprint unlock (`DeviceUnlock.kt`, `/auth/devices`, `/auth/device-login`)
1. After a password login, the app offers fingerprint unlock. The server issues a random **device token** (it stores only its SHA-256).
2. The app creates an AES key inside the **Android Keystore** with:
   - `setUserAuthenticationRequired(true)`: the hardware only lets us use the key right after a strong biometric check
   - `setInvalidatedByBiometricEnrollment(true)`: adding a new fingerprint permanently kills the key
3. It encrypts `{deviceId, deviceToken, VaultKey}` with that key and stores the result in app-private preferences.
4. To unlock: fingerprint → the hardware decrypts → `device-login` with the token → a new session.
5. **Why it's safe:** stealing the phone's storage isn't enough, because the key can't leave the hardware. And the token can be revoked from Profile → Devices.

### 5.4 Upload (`UploadScreen`, `Vault.upload`, `files.js`)
1. The user picks a file with the system picker (Storage Access Framework), so the app needs **no storage permission**. The file is refused while it is being read if it passes 50 MB; the reported size is not trusted.
2. `POST /files {size}` → the server checks the quota (250 MB per user, 200 files) and returns a random file id.
3. The phone makes a random FileKey and encrypts 1 MiB chunks (AES-GCM with the chunk label), then `PUT`s each chunk. The server accepts a chunk **only if its length is exactly right** for its position, so nobody can store extra data or overshoot their quota.
4. `commit` sends the encrypted metadata and the FileKey wrapped by the VaultKey. The server checks that every chunk is present before marking the version ready.

### 5.5 Open your own file (`openOwn` → `ViewerScreen`)
1. The phone downloads the chunks and decrypts them in memory. If any tag fails, it shows "damaged or changed by someone".
2. The **type is detected from the first bytes** (`FileType.sniff`), never from the name. A file called `x.pdf` that is really something else is not opened as a PDF.
3. Only safe built-in renderers are used:

   | Type | Renderer | Safety detail |
   |---|---|---|
   | PDF | `PdfRenderer`, page by page | On Android 11+ the decrypted PDF goes into an in-memory file (`memfd`), so it never touches storage |
   | Image | `BitmapFactory` | Size is decoded first and big images are sampled down, so a "decompression bomb" can't crash the app |
   | Text | `TextView` | Not selectable |
   | Video | `MediaPlayer` | Plays straight from memory |

4. Leaving the viewer wipes the bytes (`onClose`).

### 5.6 Share (`ShareScreen` → `ReviewScreen` → `SharedDoneScreen`, `Sharing.create`, `POST /files/:id/shares`)
1. **One merged screen** (a Phase 1 finding: the separate Permissions screen felt repetitive). It covers:
   - access: View only / View & download / Can update
   - expiry: 24 h / 7 days / 30 days / custom
   - open limit stepper
   - optional passphrase
   - notify toggle
   - a **live summary sentence**: "rahul@… can view this file (no download) up to 2 times until Sun 15 Nov…"
2. Continue → `GET /users/key?email=` returns the recipient's public key. Review shows their name and **security code** (a fingerprint of their public key) for optional in-person comparison.
3. **ECIES:**
   - The phone makes a one-time key pair.
   - ECDH with the recipient's public key gives a shared secret, and HKDF turns it into a wrapping key.
   - AES-GCM wraps the FileKey.
   - With a passphrase, the result is wrapped *again* with a PBKDF2 key derived from the passphrase.
4. The server stores the wrapped key and rules. It computes the expiry time itself (10 minutes to 30 days), and the open limit must be an integer from 1 to 50.
5. Success → "Send a heads-up" opens the Android share sheet with a `vaultspace://share/<id>` link. **The link contains no secret.** It only opens in the recipient's own logged-in app, so forwarding it gives nobody access.

### 5.7 Recipient opens (`SharedWithMeScreen.open`, `Sharing.open`, `POST /shares/:id/open`)
1. **The listing.** `GET /shares/in` lists shares addressed to *my* account. For passphrase shares, the name and wrapped key are **withheld until the passphrase is checked**. Otherwise someone could guess the passphrase offline with unlimited tries.
2. **Passphrase attempts.** The server *reserves* an attempt before checking (`pass_fails + 1 WHERE pass_fails < 5`). Twenty parallel guesses still get only 5 tries in total. On the 5th failure the share locks and the owner is notified.
3. **Counting the open.** One SQL statement:
   `UPDATE shares SET opens_used = opens_used + 1 WHERE id = ? AND revoked_at IS NULL AND expires_at > now AND opens_used < max_opens …`
   If 0 rows changed, access is denied. This is **atomic**: the test sends 20 parallel opens to a 1-open share, and exactly 1 succeeds.
4. **The viewing window.** The server returns a 5-minute token (stored hashed). Each chunk request rechecks the token *and* the share, so revoking cuts off a download already in progress.
5. **Viewing.** The viewer shows a **watermark** with the recipient's email and the time. FLAG_SECURE blocks screenshots. View-only shows no "Save a copy", and `POST /shares/:id/download` is refused for view-only anyway.

### 5.8 Revoke / stop all / expiry
- **Revoke** (`DELETE /shares/:id`) sets `revoked_at` and deletes any open viewing windows in one transaction. It is owner-only: a recipient gets a 404.
- **Stop all sharing** does the same for every active share, for one file or for the whole vault.
- **Expiry** uses the server's clock, never the phone's. A cleanup job runs every minute and logs "access expired" in the owner's history.

### 5.9 "Can update" (`Sharing.uploadVersion`, `/shares/:id/versions`)
- The recipient encrypts the new file with the same FileKey and uploads it as version N+1. The owner is notified.
- Only the last 5 versions are kept. The owner can open or **restore** any of them.
- Each person can have only one unfinished upload per file, so a recipient can't fill the owner's quota.

### 5.10 Forgot password (`ForgotScreen`, `/auth/recover/*`)
1. **Two factors are needed:** an email code *and* the recovery key. Email access alone can't take over or wipe the account.
2. The phone derives the recovery keys and sends only the proof (`rkAuth`). The server then releases the VaultKey wrapped by the recovery key, plus a 15-minute ticket.
3. The phone unwraps the VaultKey, sets a new password, and creates a **new** recovery key. The server logs out every device.

### 5.11 Change password / auto-lock / log out
- **Change password:** the phone re-wraps the VaultKey with the new KEK. Files are untouched, and other devices are logged out.
- **Auto-lock:** after 5 minutes without a touch, or 60 seconds in the background, the keys are wiped from memory and the unlock screen appears. The server also ends idle sessions after 30 minutes (and always after 12 hours).
- **Log out:** keys are wiped and the server session is deleted.

---

## 6. Security controls: threat → control → where

| Threat (what a tester will try) | Our control | Code |
|---|---|---|
| Read someone else's file by changing ids (IDOR) | Ownership is checked *inside* the SQL (`WHERE id = ? AND owner_id = ?`). Others get the same 404 as a missing file. Ids are 128-bit random | `files.js ownedFile`, `shares.js incoming` |
| Call an API without logging in | Every route must declare `public` or `user`, and the router refuses routes without it | `http.js route()` |
| SQL injection | Only prepared statements with bound parameters | `db.js` |
| Mass assignment (sending `owner_id`, `opens_used`) | The validator rejects unknown fields; server-owned fields are never read from the client | `http.js check()` |
| Prototype pollution (`__proto__`) | Rejected while parsing | `http.js readJson` |
| Huge requests / slow-loris | Byte-counted body limits (64 KB JSON, exact chunk size); header and request timeouts | `http.js readBody`, `index.js` |
| Brute-force login | Per-email growing delays and a per-IP rate limit; owner alerted after 5 failures | `auth.js` |
| Brute-force email code | 5 tries per code, 10-minute lifetime, 6 codes/hour per email | `auth.js consumeCode` |
| Discover which emails have accounts | Same response and timing everywhere; fake salts | `auth.js prelogin, login, signup` |
| Bypass open limit with parallel requests | One atomic conditional UPDATE | `shares.js /open` |
| Brute-force a share passphrase | Server-checked, 5 attempts reserved atomically; key hidden until passed | `shares.js` |
| Keep access after revoke | Revoke kills open windows; every chunk rechecks the share | `shares.js openWindow` |
| Change expiry or limits from the client | The server computes expiry from its own clock; strict bounds | `shares.js` |
| Spoof IP to dodge rate limits | `X-Forwarded-For` trusted only from a local proxy | `http.js clientIp` |
| Stolen database | Only scrypt hashes, SHA-256 token hashes, HMAC code hashes, wrapped keys and ciphertext | everywhere |
| Curious server admin | Zero-knowledge: contents *and* names are encrypted on the phone | `Crypto.kt`, `Data.kt` |
| Tamper with or reorder chunks | AES-GCM with position labels | `Data.kt aad()` |
| Edit the access history | Hash chain; "Verify history" detects any change | `db.js logEvent, verifyChain` |
| Network interception (Burp, fake Wi-Fi) | HTTPS only; app trusts **only** our certificate (pinning); user CAs not trusted | `network_security_config.xml`, `Api.kt` |
| Screenshots / screen recording | FLAG_SECURE on the window *and* every dialog; release builds force it on | `MainActivity.kt` |
| Tapjacking (overlay tricks) | `filterTouchesWhenObscured` on the root view | `MainActivity.buildShell` |
| Task hijacking (StrandHogg) | `taskAffinity=""` | `AndroidManifest.xml` |
| Backup extraction (`adb backup`) | `allowBackup=false`, no data extraction | manifest, `data_extraction_rules.xml` |
| Keyboard learning secrets | `IME_FLAG_NO_PERSONALIZED_LEARNING`, no autofill on recovery keys | `Ui.kt input()` |
| Secrets left in clipboard | Marked sensitive (hidden in previews), cleared after 60 s | `MainActivity.copySecret` |
| Malicious file names (`U+202E` "fdp.exe" trick) | Control and bidi characters stripped on server and phone | `util.js cleanText`, `Data.kt cleanName` |
| Malicious files (HTML/SVG pretending to be PDF) | Type sniffed from bytes; only safe renderers; server serves chunks as sandboxed attachments | `FileType`, `http.js send` |
| Huge image crashes viewer | Decode bounds first, then downsample | `ViewerScreen.showImage` |
| Logs leaking secrets | No `Log` calls at all, and R8 strips any in release | `proguard-rules.pro` |
| Someone with your unlocked phone | Auto-lock at 5 minutes; re-auth for recovery key, delete, 2FA, devices | `MainActivity`, `withPassword` |
| Server hijacked by a peer (OS level) | systemd sandbox, non-root user, firewall, auto security updates, checksum-verified Node | `deploy/` |

---

## 7. File-by-file tour

### Server (`server/src`)
| File | Job |
|---|---|
| `index.js` | Starts HTTPS (TLS 1.2+), sets timeouts, runs `cleanup()` every minute |
| `app.js` | Request pipeline: route → per-IP limit → authenticate → handler → JSON. Unknown errors become a generic message plus a reference id. Also `cleanup()` |
| `http.js` | Our mini-framework: `route()` (auth must be declared), `readBody()` (byte-counted limit), `readJson()` (rejects `__proto__`), validators `V.*`, `check()`, `limit()` (rate limiter), `clientIp()`, security headers |
| `auth.js` | Sessions, codes, prelogin, sign-up, login, lockout, trusted devices, recovery, profile, password change, recovery-key view, account delete, TOTP |
| `files.js` | Upload (reserve → chunks → commit), list, details, download chunks, rename/category, restore, delete |
| `shares.js` | Public-key lookup, create, list (out/in), revoke, stop all, open (atomic), viewing window, download permission, "Can update" uploads |
| `activity.js` | History, verify chain, notifications |
| `db.js` | SQLite schema, prepared-statement cache, transactions, hash-chained `logEvent()` |
| `storage.js` | Chunk files on disk; paths built only from validated ids (no path traversal) |
| `mail.js` | Our own SMTP-over-TLS client, or the Brevo HTTPS API; dev mode prints codes |
| `util.js` | Random ids/tokens, SHA-256, HMAC, scrypt hashing, constant-time compare, P-256 check, `cleanText`, AES-GCM seal for TOTP secrets, base32, TOTP |
| `config.js` | Settings and limits; creates the 32-byte server secret on first run |

### App (`android/app/src/main/java/com/vaultspace/app`)
| File | Job |
|---|---|
| `MainActivity.kt` | The only Activity. Screen stack (push/replace/reset/back), background `task()` runner with busy overlay, errors → friendly messages, dialogs (all FLAG_SECURE), file picker, auto-lock, biometric enrol/unlock, deep links, sensitive clipboard |
| `Ui.kt` | Our layout DSL (`column`, `row`, `text`, `button`, `input`, `chips`, `card`…), colours, `Watermark`, `Fmt` helpers |
| `Crypto.kt` | Key derivation, AES-GCM, ECIES, fingerprints, `RecoveryKey` (Crockford base32), `PasswordCheck` |
| `Data.kt` | `Session` (memory-only keys), `Prefs`, `Meta`, `Vault` (upload/download/chunks), `Sharing`, `FileType` sniffing |
| `Api.kt` | HTTPS client on `HttpsURLConnection` |
| `DeviceUnlock.kt` | Keystore key + `BiometricPrompt` |
| `AuthScreens.kt` | Login, sign-up, recovery key, forgot password, strength meter |
| `VaultScreens.kt` | Home, upload, file details (access, versions), viewer (PDF/image/text/video) |
| `ShareScreens.kt` | Share, review, done, Shared By Me, Shared With Me |
| `AccountScreens.kt` | Notifications, history, profile, 2FA, devices, change password, "what we protect" |

---

## 8. What VaultSpace can't protect (say this confidently; it's a strength)

- **A photo of the screen taken with another phone.** That's why viewed files carry a watermark naming the viewer.
- **Copies already saved** when the owner allowed downloads. The app says so on every revoke screen.
- **Someone holding your unlocked phone.** Auto-lock limits this window.
- **A rooted phone or modified app** can keep the decrypted bytes it was allowed to view. The *server* rules still hold (no extra opens, no access after revoke).
- **Metadata the server can see:** file sizes, timestamps, who shares with whom, and when files are opened. It never sees names or contents.
- **A malicious server could hand out a fake public key** (a man-in-the-middle on sharing). The **security code** lets two people compare keys in person, like Signal's safety numbers.
- **Forgetting both password and recovery key** means the files are gone. That's the price of zero-knowledge, and it's explained up front.
- **Password rules run on the phone**, because the server never sees the password. A modified app could pick a weak password, but only for its own account.

---

## 9. Likely viva questions (with short answers)

1. **Why is the server unable to read files?** They're encrypted on the phone with keys derived from the password, which the server never receives. The server stores only ciphertext and wrapped keys.
2. **What does the server store for my password?** `scrypt(authKey)`. The authKey itself comes from PBKDF2 + HKDF, so it's different from the KEK that decrypts the vault.
3. **Why two derived keys (authKey, KEK)?** So proving your password to the server never gives the server the decryption key.
4. **Why PBKDF2 with 600,000 rounds?** It makes every password guess cost about a second of computation. 600,000 is OWASP's 2023 figure. Argon2 would be better but isn't built into Android.
5. **What's a salt and why random per user?** It stops precomputed tables and makes identical passwords produce different keys.
6. **Why AES-GCM?** It's authenticated encryption: any change to the ciphertext is detected (the tag), not just hidden.
7. **What is the AAD for?** It binds each ciphertext to its context (file, version, chunk position), so ciphertexts can't be swapped, reordered or truncated.
8. **How does sharing work without the server seeing the key?** ECIES. A one-time EC key pair does ECDH with the recipient's public key, HKDF derives a key, and AES-GCM wraps the FileKey. Only the recipient's private key can redo the ECDH.
9. **Where is the user's private key kept?** It's encrypted by the VaultKey and stored on the server, so it works on a new phone after login. It's decrypted only in memory.
10. **How is the open limit enforced?** By one atomic SQL UPDATE with the conditions in its WHERE clause. 0 rows changed means denied. It's tested with 20 parallel requests.
11. **What if the recipient edits the app to skip the limit?** The ciphertext is released only by the server, after the atomic check. The app can't skip a server check.
12. **Can a recipient brute-force the passphrase?** No. The wrapped key is only released after the server checks the passphrase proof, there are 5 attempts reserved atomically, and then the share locks.
13. **How does revoke work instantly?** It sets `revoked_at` and deletes viewing windows. Every chunk request rechecks the share.
14. **What stops screenshots?** `FLAG_SECURE` on the activity window and on every dialog window. Recent-apps previews are blank too.
15. **How is the server certificate trusted?** The app ships with our self-signed certificate and trusts only it (network security config). Interception proxies and user-installed CAs are rejected.
16. **How do you prevent account enumeration?** Identical responses, fake stable salts, scrypt run for unknown users, and signup emails that differ only in the inbox.
17. **What happens on 5 wrong logins?** Growing delays per email (never permanent), a per-IP limit, and an alert in the owner's history.
18. **How does fingerprint unlock keep the vault key safe?** It's encrypted with a Keystore key that can only be used after a strong biometric and is invalidated if fingerprints change. The device token can be revoked server-side.
19. **What is the recovery key and why 160 bits?** A random key that wraps a second copy of the VaultKey. 160 bits can't be brute-forced, unlike the Phase 1 `apple-vinegar-67901`.
20. **Why does recovery need both email and recovery key?** Inbox access alone (a common compromise) shouldn't let anyone reset the account.
21. **How is the history tamper-evident?** Each entry stores `SHA-256(previous hash | its fields)`. Changing an old entry breaks every later hash, and "Verify history" recomputes the chain.
22. **What is TOTP and why store `totp_last`?** A 6-digit code from HMAC(secret, time/30). Remembering the last used step stops a code from being replayed.
23. **How do you stop path traversal?** Disk paths are built only from server-generated ids (checked against `^[A-Za-z0-9_-]{22}$`) and integers, never from client text.
24. **Why does every route declare 'public'/'user'?** Deny-by-default. A forgotten check can't make an endpoint public.
25. **What's mass assignment and how is it blocked?** Clients sending extra fields like `owner_id`. Our validator rejects any field not in the schema.
26. **Why sniff file types from bytes?** The name or claimed MIME type can lie. A file named `.pdf` might be HTML; we only render real PDFs, images, text and video.
27. **How does the PDF viewer avoid writing decrypted files to disk?** It uses `memfd_create`, an in-memory file, on Android 11+. Older phones use a temp file deleted immediately after opening.
28. **What's the biggest remaining risk?** Things outside any app: photos of the screen, a compromised phone, users choosing to save copies. We reduce them with the watermark, auto-lock and clear warnings.
29. **How is 50% original code satisfied?** All about 4,900 lines are ours; the app and server have zero third-party dependencies (`dependencies { }` is empty).
30. **How did Phase 1 change the design?**
    - merged Share/Permissions screen
    - labelled navigation
    - "Only you / Shared · 2" tags
    - recovery key
    - fingerprint unlock
    - confirmations before revoke and delete
    - download off by default
    - passphrase optional
    - limits explained in plain words

---

## 10. Glossary
- **Zero-knowledge / end-to-end:** only the users' phones can decrypt; the server can't.
- **Wrap a key:** encrypt one key with another.
- **KEK:** key-encryption key.
- **Nonce:** a number used once.
- **Salt:** random input to a password hash.
- **ECDH:** two parties derive the same secret from their key pairs.
- **ECIES:** ECDH + a key derivation + symmetric encryption, used to "encrypt to a public key".
- **IDOR:** insecure direct object reference; accessing others' data by changing an id.
- **Enumeration:** discovering which accounts exist.
- **Race condition:** two requests interleaving so that a check passes twice.
- **Certificate pinning:** trusting only a specific certificate.
- **FLAG_SECURE:** an Android window flag that blocks screenshots and recording.
- **Keystore:** Android's hardware-backed key storage.
- **Crypto-shredding:** making data unreadable by destroying its key.

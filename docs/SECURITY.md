# VaultSpace security design

This document is the source for Part B of the final presentation. The detailed explanations are in [VIVA_GUIDE.md](VIVA_GUIDE.md).

## 1. Security requirements (from the Phase 1 studies)

| ID | Requirement | Phase 1 evidence | How it is met |
|---|---|---|---|
| SR1 | Files stay confidential even if the server or its database leaks | Most respondents chose "the provider can't open my files" | End-to-end encryption on the phone; file names and categories are encrypted too |
| SR2 | Only the intended recipient can open a share | Forwarding/misuse was the top worry (9/24); 37.7% had a document reach unintended people | The file key is wrapped for the recipient's public key (ECIES); a forwarded link is useless; optional passphrase |
| SR3 | The sender's limits really hold | Expiry 82.6%, open limits 52.2%, revoking 52.2% | Server-side, atomic enforcement on every request; revoke takes effect immediately |
| SR4 | Owners see who accessed what | 46.4% wanted history and alerts | Hash-chained, append-only history; in-app notifications; email alerts for logins |
| SR5 | Strong but low-friction login | 27.5% skipped slow security steps; biometric requests (P05, P09) | Password + fingerprint unlock (Keystore); optional TOTP; brute-force delays; no enumeration |
| SR6 | Recovery without giving up privacy | 27.5% had been locked out | A 160-bit recovery key wraps the vault key; reset needs both the email code and the recovery key |
| SR7 | Files can't be changed silently | 29.1% wanted change warnings | AES-GCM with position labels; versions; "new version" notifications |
| SR8 | Sessions can't be hijacked or left open | – | Hashed tokens; 30-min idle and 12-h absolute timeouts; 5-min auto-lock; log out everywhere |
| SR9 | Untrusted input can't attack users or the server | – | Strict validation, prepared statements, type sniffing, safe renderers |
| SR10 | The service survives abuse | Shared test server | Quotas, exact chunk sizes, rate limits, timeouts |
| SR11 | Minimal data collection | Privacy concerns | Only email and name; no analytics; encrypted metadata |
| SR12 | Limits are explained honestly at the moment of decision | 18.2% missed the revoke notice; screenshot worries | Notices on share, review, revoke and viewer; "What VaultSpace protects" page |

## 2. Threat model

**Assets**
- File contents and names
- The VaultKey, FileKeys and private keys
- Passwords, recovery keys and sessions
- Share rules
- The access history

**Adversaries**
1. Other users and peer testers with their own accounts
2. A recipient trying to exceed their permissions
3. Whoever obtains a forwarded link or message
4. A network attacker
5. A thief with the phone
6. Someone who steals the database or blobs, or a curious administrator
7. Someone trying to fill the disk or flood the server

**Trust assumptions**
- The user's own phone OS is not compromised.
- The recipient's account belongs to the recipient. The security code allows an optional in-person check.

## 3. Controls

See the threat → control → code table in [VIVA_GUIDE.md §6](VIVA_GUIDE.md#6-security-controls-threat--control--where).

## 4. Verification

`server/test/api.test.js` runs 21 tests and `server/test/mail.test.js` 2 more (`npm test`):
- security headers and sandboxed chunk downloads
- input validation (unknown fields, `__proto__`, wrong types, oversized bodies, path traversal)
- no account enumeration (prelogin, login, signup)
- sessions end on logout; garbage tokens are rejected
- email codes die after 5 wrong guesses
- access control: other users can't see, download, delete or restore my files
- exact chunk sizes and quota
- open limit under 20 parallel requests
- view-only download refused; revoke cuts an open window; a stolen viewing token is useless to someone else
- server-clock expiry
- bad share rules rejected (0 opens, decimals, negative expiry, unknown permission, garbage keys, sharing with yourself)
- passphrase: key hidden until checked; locks after 5 parallel guesses
- "Can update" only for edit shares; abandoned uploads can't exhaust the quota
- "Can update" can't skip the passphrase, and stops once the share is locked
- "Can update" can't wipe the owner's original version
- a two-factor code works once, even when two logins race with it
- fingerprint logins appear in the access history
- recovery needs both factors and logs out everywhere
- TOTP matches the RFC 6238 test vector
- hash chain detects tampering
- login alert emails are rationed, so repeated logins can't use up the mail quota
- the mail client survives the server's goodbye and reports a wrong App Password

End-to-end checks on the emulator:
- sign-up → upload → view
- share with a passphrase → wrong passphrase → right passphrase → watermark
- the server database contains no file names, and the chunks are random bytes

## 5. Known limitations

See [VIVA_GUIDE.md §8](VIVA_GUIDE.md#8-what-vaultspace-cant-protect-say-this-confidently-its-a-strength). These limitations are also shown in the app, under Profile → "What VaultSpace can and can't protect".

Design decisions a tester may report, and why we accept them:
- **"View only" is enforced by the app, not the server.** To show a file, the phone must get its key and ciphertext, so a modified app could keep a copy. The server enforces everything it can: expiry, opens, passphrase, revoke.
- **The history chain is unkeyed.** It detects edits to old entries, but someone with write access to the database (the server administrator) could rebuild the whole chain.
- **Shares aren't signed by the sender.** A malicious server could hand out a fake share or a fake public key. The security code (compare in person) detects a swapped key.
- **Recovery skips the authenticator code.** It already needs two factors: the email inbox and the 160-bit recovery key. Requiring the authenticator too would lock out anyone who lost their phone.
- **`GET /users/key` tells a logged-in user whether an email has an account.** Sharing needs this. It is limited to 60 lookups per hour.
- **Backups keep deleted data (still encrypted) for 7 days.** The keys that could decrypt it are only on users' phones.

## 6. Security audit (16 Nov 2026)

We reviewed every server and app file before peer testing. Findings and fixes:

| # | Finding | Severity | Fix | Verified by |
|---|---|---|---|---|
| A1 | A "Can update" recipient could upload versions without ever entering the passphrase, and even after the share locked | Medium | Starting an update needs a current viewing window, which only a passphrase-checked, counted open creates; locked shares refuse updates | new API test; emulator |
| A2 | A "Can update" recipient could upload 5 versions and so prune away all of the owner's own versions | Medium | Pruning always keeps the owner's newest version | new API test (fails on the old code) |
| A3 | Two logins racing with the same authenticator code could both succeed | Low | The "code used" check is one conditional UPDATE | new API test (fails on the old code) |
| A4 | A `vaultspace://share/…` link (which any website or app can fire) opened the share at once, using up one of the recipient's opens | Medium | Links always ask first, saying how many opens it uses | emulator |
| A5 | "Shared With Me" showed only the sender's self-chosen display name, so anyone could appear as "Prof. Sharma" | Medium | The verified email is shown next to the name everywhere | emulator |
| A6 | Dialogs (Delete, Revoke…) weren't protected against tapjacking; other apps' overlays weren't hidden | Low | Dialogs ignore obscured taps; overlays hidden on Android 12+ | code review |
| A7 | Apps with accessibility access could read file names and contents (FLAG_SECURE doesn't stop them) | Low | Screens marked accessibility-data-sensitive on Android 14+; real accessibility tools such as TalkBack still work | code review; the UI test tool can still read every screen |
| A8 | With the file picker open, the vault never auto-locked | Low | Locks after 10 minutes in the picker | code review |
| A9 | One dialog (Category) and the video surface weren't explicitly screenshot-protected | Low | Both now secure | emulator |
| A10 | The 2FA setup key went to any app claiming `otpauth:` links | Low | The user picks the app from a chooser | emulator |
| A11 | A chunk arriving after its upload was committed or cancelled was still written | Low | Upload state is rechecked after the body arrives | code review |
| A12 | Many parallel chunk uploads could use up server memory; connections were unlimited | Low | At most 4 chunks in flight per user; 1000 connections | code review |
| A13 | Flooding the rate limiter with made-up keys reset everyone's counters | Low | Expired counters are pruned; live ones are never wiped | code review |
| A14 | Fingerprint logins weren't recorded in the history | Low | Logged as "login (fingerprint)" | new API test |
| A15 | The in-app "what's protected" page claimed the server enforces view-only | Info | Text corrected; limitation listed | review |
| A16 | Server sandbox exposure score 4.9 | Hardening | System-call filter, namespaces, address families, /proc hiding; score 1.5; full test suite run inside the same sandbox on the VM | `systemd-analyze security`; tests on the VM |
| A17 | SSH on the VM accepts passwords from the whole campus network | Medium | Use key login only (see README "Deploy") | config check |

### Second review (17 Nov 2026)

| # | Finding | Severity | Fix | Verified by |
|---|---|---|---|---|
| A18 | A "Can update" recipient could upload a version whose name and type can't be decrypted. The owner's app then failed to show *any* file, and the file couldn't be restored from the app | Medium | Each file is decrypted on its own. A broken one is listed as "Unreadable file" and its page offers Restore and Rename; other files are unaffected | attack replayed against a local server; owner's app on the emulator lists every file and restores the old version |

### Peer testing (18–25 Nov 2026)

75 rows of the course's bug sheet were filed under Group 15:
- 8 describe other groups' apps, and 2 are word-for-word duplicates.
- 24 were disproved by retesting, 20 are documented limitations or deliberate design, and 12 are suggestions.
- 9 were accepted. They are 8 distinct issues, and none exposes a file, a key or an account.

The accepted issue with real impact was fixed on the server:

| # | Finding | Severity | Fix | Verified by |
|---|---|---|---|---|
| A19 | Every login sent an alert email. One tester logged in about 620 times in two hours (19 Nov), the mail provider's daily quota ran out, and sign-up and recovery codes stopped arriving for about 18 hours (report 1517) | Medium (availability only) | Alert emails (new login, password changed, password reset, 2FA off) go out at most once per kind per account per hour, and 200 a day in total; every event still appears in the app | new API test (fails on the old code with 5 emails, passes with 1); VM logs |

Accepted, low severity, not yet changed in the app:
- 1468: password-protected PDFs are reported as "may be damaged".
- 1479: the app accepts a lower PBKDF2 iteration count from the server; only an attacker who controls the server could send one.
- 1482: the owner's viewer caption says "only you can open it" even when the file is shared.
- 1483: placeholder text contrast is 2.81:1; field labels meet AA.
- 1485: "yesterday" means "24–48 hours ago"; the history shows exact times.
- 1513 and 1528: files without a preview can't be read through a View-only share.
- 1514: leetspeak variants of common passwords pass the blocklist.

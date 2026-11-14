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

`server/test/api.test.js` runs 16 tests:
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
- recovery needs both factors and logs out everywhere
- TOTP matches the RFC 6238 test vector
- hash chain detects tampering

End-to-end checks on the emulator:
- sign-up → upload → view
- share with a passphrase → wrong passphrase → right passphrase → watermark
- the server database contains no file names, and the chunks are random bytes

## 5. Known limitations

See [VIVA_GUIDE.md §8](VIVA_GUIDE.md#8-what-vaultspace-cant-protect-say-this-confidently-its-a-strength). These limitations are also shown in the app, under Profile → "What VaultSpace can and can't protect".

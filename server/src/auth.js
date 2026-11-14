// Accounts, logins, sessions, recovery, trusted devices and two-factor authentication.
// The server never receives the user's password. The app derives an "authKey" from it
// (PBKDF2 + HKDF) and the server stores only a scrypt hash of that key.
import crypto from 'node:crypto';
import { LIMITS } from './config.js';
import { route, readJson, V, fail, limit } from './http.js';
import { get, all, run, tx, logEvent } from './db.js';
import { sendMail } from './mail.js';
import * as store from './storage.js';
import {
  now, newId, newToken, sha256, hmac, sameText, hashSecret, checkSecret, isP256, cleanText,
  sixDigits, seal, unseal, base32, unbase32, totpAt, ID_RE, TOKEN_RE,
} from './util.js';

const KEY32 = V.b64(32);              // authKey / recovery proof: 32 bytes
const VAULT_BLOB = V.b64(60);         // 12-byte nonce + 32-byte key + 16-byte tag
const CODE = V.str(6, 6, /^\d{6}$/);
const NAME = V.str(1, 60);

// ---- sessions ------------------------------------------------------------------
// The app sends "Authorization: Bearer <token>". We store only SHA-256(token), so a
// database leak does not hand out working sessions.
export function createSession(userId, label) {
  const token = newToken();
  run('INSERT INTO sessions (token_hash, user_id, label, created_at, last_seen) VALUES (?, ?, ?, ?, ?)',
    sha256(token), userId, label, now(), now());
  return token;
}

export function authenticate(ctx) {
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(ctx.req.headers.authorization || '');
  if (!m) fail(401, 'Please log in.');
  const s = get('SELECT * FROM sessions WHERE token_hash = ?', sha256(m[1]));
  const t = now();
  if (!s || t - s.last_seen > LIMITS.sessionIdle || t - s.created_at > LIMITS.sessionMax) {
    if (s) run('DELETE FROM sessions WHERE token_hash = ?', s.token_hash);
    fail(401, 'Your session ended. Please unlock again.');
  }
  run('UPDATE sessions SET last_seen = ? WHERE token_hash = ?', t, s.token_hash);
  ctx.session = s;
  ctx.user = get('SELECT * FROM users WHERE id = ?', s.user_id) || fail(401, 'Please log in.');
}

const deviceLabel = (ctx) => cleanText(String(ctx.req.headers['x-device'] || '')).slice(0, 60) || 'Unknown device';

const account = (u) => ({
  id: u.id, email: u.email, name: u.name, createdAt: u.created_at,
  notifyOpen: !!u.notify_open, twoFactor: !!u.totp_secret,
});

// What the app needs right after logging in: the session plus the user's wrapped keys,
// which only the user's password (or device key) can unwrap.
const loginPayload = (u, token) => ({
  token,
  account: account(u),
  keys: { vaultByPw: u.vault_by_pw, privByVault: u.priv_by_vault, pubKey: u.pub_key },
});

// Sensitive actions ask for the password again ("re-authentication").
export async function requirePassword(ctx, authKey) {
  limit(`reauth:${ctx.user.id}`, 10, 900);
  if (!(await checkSecret(authKey, ctx.user.auth_salt, ctx.user.auth_hash))) fail(403, 'Your password is incorrect.');
}

// ---- one-time codes sent by email ---------------------------------------------
// Stored as an HMAC, valid for 10 minutes, single use, and dead after 5 wrong tries.
const codeHash = (purpose, email, code) => hmac(`${purpose}|${email}|${code}`).toString('base64url');

function storeCode(purpose, email, code, ttl = LIMITS.codeTtl) {
  run('INSERT OR REPLACE INTO codes (purpose, email, hash, expires_at, attempts) VALUES (?, ?, ?, ?, 0)',
    purpose, email, codeHash(purpose, email, code), now() + ttl);
}

function issueCode(purpose, email, ip) {
  limit(`code-ip:${ip}`, 30, 3600);
  limit(`code-mail:${email}`, 6, 3600);   // stops anyone using us to flood an inbox
  const code = sixDigits();
  storeCode(purpose, email, code);
  return code;
}

// Synchronous on purpose: no other request can run between the check and the update,
// so parallel guesses cannot get more than 5 tries.
function consumeCode(purpose, email, code) {
  const c = get('SELECT * FROM codes WHERE purpose = ? AND email = ?', purpose, email);
  if (!c || c.expires_at < now()) fail(400, 'This code has expired. Ask for a new one.');
  if (c.attempts >= 5) fail(400, 'Too many wrong codes. Ask for a new one.');
  if (!sameText(c.hash, codeHash(purpose, email, code))) {
    run('UPDATE codes SET attempts = attempts + 1 WHERE purpose = ? AND email = ?', purpose, email);
    fail(400, 'That code is incorrect.');
  }
  run('DELETE FROM codes WHERE purpose = ? AND email = ?', purpose, email);
}

// ---- brute-force protection for logins -------------------------------------------
// Kept per email in memory, whether or not the account exists (so it reveals nothing).
// Growing delays instead of a permanent lock, so an attacker cannot lock a victim out for good.
const failures = new Map();
function checkLockout(email) {
  const f = failures.get(email);
  if (f && Date.now() < f.until) {
    fail(429, `Too many attempts. Try again in ${Math.ceil((f.until - Date.now()) / 60000)} minute(s).`);
  }
}
function noteFailure(email, user) {
  if (failures.size > 100_000) failures.clear();
  const f = failures.get(email) || { n: 0, until: 0 };
  f.n++;
  if (f.n >= 5) f.until = Date.now() + Math.min(2 ** (f.n - 5) * 30_000, 15 * 60_000);
  failures.set(email, f);
  if (user && f.n === 5) logEvent(user.id, 'login_failed_many', { notify: true });
}

// ---- prelogin: which salt to use ----------------------------------------------------
// Unknown emails get a fake salt derived from a server secret. It is stable, so asking twice
// gives the same answer, and it looks exactly like a real one: no account enumeration.
route('POST', '/auth/prelogin', 'public', async (ctx) => {
  limit(`pre:${ctx.ip}`, 60, 300);
  const { email } = await readJson(ctx.req, { email: V.email() });
  const u = get('SELECT kdf_salt, kdf_iters FROM users WHERE email = ?', email);
  if (u) return { salt: u.kdf_salt, iters: u.kdf_iters };
  return { salt: hmac(`salt|${email}`).subarray(0, 16).toString('base64url'), iters: LIMITS.kdfIters };
});

// ---- sign up -------------------------------------------------------------------
route('POST', '/auth/signup/start', 'public', async (ctx) => {
  const { email } = await readJson(ctx.req, { email: V.email() });
  const code = issueCode('signup', email, ctx.ip);   // a code is stored even for existing emails (same behaviour)
  if (get('SELECT 1 FROM users WHERE email = ?', email)) {
    sendMail(email, 'Someone tried to create a VaultSpace account with your email',
      'Someone tried to sign up to VaultSpace with this email address, but you already have an account.\n\n'
      + 'If it was you, just log in. If not, you can ignore this message; nothing has changed.');
  } else {
    sendMail(email, `${code} is your VaultSpace code`,
      `Your VaultSpace verification code is ${code}.\nIt expires in 10 minutes.\n\nIf you did not ask for this, ignore this email.`);
  }
  return { ok: true };
});

route('POST', '/auth/signup/finish', 'public', async (ctx) => {
  limit(`signup:${ctx.ip}`, 30, 86400);
  const b = await readJson(ctx.req, {
    email: V.email(), code: CODE, name: NAME,
    kdfSalt: V.b64(16), authKey: KEY32,
    vaultByPw: VAULT_BLOB, vaultByRk: VAULT_BLOB, rkAuth: KEY32, rkByVault: V.b64(48),
    pubKey: V.b64(91), privByVault: V.b64(60, 300),
  });
  const name = cleanText(b.name);
  if (!name) fail(400, 'Please enter your name.');
  if (!isP256(b.pubKey)) fail(400, 'Invalid public key.');
  consumeCode('signup', b.email, b.code);   // proves the person owns this inbox
  if (get('SELECT 1 FROM users WHERE email = ?', b.email)) fail(409, 'An account with this email already exists. Log in instead.');
  const auth = await hashSecret(b.authKey);
  const rk = await hashSecret(b.rkAuth);
  const id = newId();
  run(`INSERT INTO users (id, email, name, created_at, kdf_salt, kdf_iters, auth_salt, auth_hash, rk_salt, rk_hash,
       vault_by_pw, vault_by_rk, rk_by_vault, pub_key, priv_by_vault) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  id, b.email, name, now(), b.kdfSalt, LIMITS.kdfIters, auth.salt, auth.hash, rk.salt, rk.hash,
  b.vaultByPw, b.vaultByRk, b.rkByVault, b.pubKey, b.privByVault);
  logEvent(id, 'account_created', { actor: deviceLabel(ctx) });
  const u = get('SELECT * FROM users WHERE id = ?', id);
  return loginPayload(u, createSession(id, deviceLabel(ctx)));
});

// ---- log in / log out ------------------------------------------------------------
route('POST', '/auth/login', 'public', async (ctx) => {
  const b = await readJson(ctx.req, { email: V.email(), authKey: KEY32, totp: V.opt(CODE) });
  limit(`login-ip:${ctx.ip}`, 40, 300);
  checkLockout(b.email);
  const u = get('SELECT * FROM users WHERE email = ?', b.email);
  const ok = await checkSecret(b.authKey, u?.auth_salt, u?.auth_hash);
  if (!u || !ok) {
    noteFailure(b.email, u);
    fail(401, 'Email or password is incorrect.');   // same message whether or not the account exists
  }
  if (u.totp_secret) {
    if (!b.totp) fail(401, 'Enter the 6-digit code from your authenticator app.', { need2fa: true });
    if (!checkTotp(u, u.totp_secret, b.totp)) {
      noteFailure(b.email, u);
      fail(401, 'That authenticator code is incorrect.', { need2fa: true });
    }
  }
  failures.delete(b.email);
  const label = deviceLabel(ctx);
  logEvent(u.id, 'login', { actor: label, notify: true });
  sendMail(u.email, 'New login to VaultSpace',
    `Your VaultSpace account was just used to log in on: ${label}.\n\n`
    + 'If this was not you, open VaultSpace > Profile > Devices & sessions, log out everywhere and change your password.');
  return loginPayload(u, createSession(u.id, label));
});

route('POST', '/auth/logout', 'user', (ctx) => {
  run('DELETE FROM sessions WHERE token_hash = ?', ctx.session.token_hash);
  return { ok: true };
});

// ---- trusted devices (fingerprint / face unlock) -----------------------------------
// After a password login the app can register itself. It gets a random device token, which it
// keeps encrypted by a key in the phone's secure hardware that only unlocks with a biometric.
route('POST', '/auth/devices', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32 });
  await requirePassword(ctx, b.authKey);
  if (get('SELECT COUNT(*) AS n FROM devices WHERE user_id = ?', ctx.user.id).n >= 10) fail(400, 'Remove an old device first.');
  const id = newId(), token = newToken(), label = deviceLabel(ctx);
  run('INSERT INTO devices (id, user_id, token_hash, label, created_at, last_used) VALUES (?, ?, ?, ?, ?, ?)',
    id, ctx.user.id, sha256(token), label, now(), now());
  logEvent(ctx.user.id, 'device_added', { actor: label, notify: true });
  return { deviceId: id, deviceToken: token };
});

route('POST', '/auth/device-login', 'public', async (ctx) => {
  limit(`device:${ctx.ip}`, 30, 300);
  const b = await readJson(ctx.req, { deviceId: V.str(22, 22, ID_RE), deviceToken: V.str(43, 43, TOKEN_RE) });
  const d = get('SELECT * FROM devices WHERE id = ?', b.deviceId);
  if (!d || !sameText(d.token_hash, sha256(b.deviceToken))) fail(401, 'This phone is no longer trusted. Log in with your password.');
  run('UPDATE devices SET last_used = ? WHERE id = ?', now(), d.id);
  const u = get('SELECT * FROM users WHERE id = ?', d.user_id);
  return loginPayload(u, createSession(u.id, d.label));
});

route('GET', '/devices', 'user', (ctx) => ({
  devices: all('SELECT id, label, created_at AS createdAt, last_used AS lastUsed FROM devices WHERE user_id = ? ORDER BY last_used DESC', ctx.user.id),
}));

route('DELETE', '/devices/:id', 'user', (ctx) => {
  const r = run('DELETE FROM devices WHERE id = ? AND user_id = ?', ctx.params.id, ctx.user.id);
  if (r.changes !== 1) fail(404, 'Device not found.');
  logEvent(ctx.user.id, 'device_removed');
  return { ok: true };
});

// ---- forgot password: email code AND recovery key ------------------------------------
// Both are required, so someone who only has access to the inbox cannot take over or wipe the account.
route('POST', '/auth/recover/start', 'public', async (ctx) => {
  const { email } = await readJson(ctx.req, { email: V.email() });
  const code = issueCode('recover', email, ctx.ip);
  if (get('SELECT 1 FROM users WHERE email = ?', email)) {
    sendMail(email, `${code} is your VaultSpace recovery code`,
      `Your VaultSpace recovery code is ${code}. It expires in 10 minutes.\n\n`
      + 'You will also need your recovery key. If you did not ask for this, ignore this email.');
  }
  return { ok: true };
});

route('POST', '/auth/recover/verify', 'public', async (ctx) => {
  const b = await readJson(ctx.req, { email: V.email(), code: CODE, rkAuth: KEY32 });
  checkLockout(b.email);
  consumeCode('recover', b.email, b.code);
  const u = get('SELECT * FROM users WHERE email = ?', b.email);
  if (!u || !(await checkSecret(b.rkAuth, u.rk_salt, u.rk_hash))) {
    noteFailure(b.email, u);
    fail(400, 'The recovery key is incorrect.');
  }
  const ticket = newToken();
  storeCode('ticket', b.email, ticket, 15 * 60);
  return { ticket, vaultByRk: u.vault_by_rk };
});

route('POST', '/auth/recover/finish', 'public', async (ctx) => {
  const b = await readJson(ctx.req, {
    email: V.email(), ticket: V.str(43, 43, TOKEN_RE),
    kdfSalt: V.b64(16), authKey: KEY32, vaultByPw: VAULT_BLOB,
    rkAuth: KEY32, vaultByRk: VAULT_BLOB, rkByVault: V.b64(48),
  });
  consumeCode('ticket', b.email, b.ticket);
  const u = get('SELECT * FROM users WHERE email = ?', b.email) || fail(400, 'Account not found.');
  const auth = await hashSecret(b.authKey);
  const rk = await hashSecret(b.rkAuth);
  tx(() => {
    run(`UPDATE users SET kdf_salt = ?, auth_salt = ?, auth_hash = ?, vault_by_pw = ?, rk_salt = ?, rk_hash = ?,
         vault_by_rk = ?, rk_by_vault = ? WHERE id = ?`,
    b.kdfSalt, auth.salt, auth.hash, b.vaultByPw, rk.salt, rk.hash, b.vaultByRk, b.rkByVault, u.id);
    run('DELETE FROM sessions WHERE user_id = ?', u.id);   // log out everywhere
    run('DELETE FROM devices WHERE user_id = ?', u.id);
  });
  logEvent(u.id, 'recovered', { actor: deviceLabel(ctx), notify: true });
  sendMail(u.email, 'Your VaultSpace password was reset',
    'Your password was reset with your recovery key, and every device was logged out. You also have a new recovery key.\n\n'
    + 'If this was not you, contact the VaultSpace team immediately.');
  return loginPayload(get('SELECT * FROM users WHERE id = ?', u.id), createSession(u.id, deviceLabel(ctx)));
});

// ---- account and profile ----------------------------------------------------------
const usage = (userId) => get(
  'SELECT COALESCE(SUM(v.size), 0) AS used, COUNT(DISTINCT f.id) AS files FROM files f LEFT JOIN versions v ON v.file_id = f.id WHERE f.owner_id = ?',
  userId,
);

route('GET', '/me', 'user', (ctx) => ({ account: account(ctx.user), usage: { ...usage(ctx.user.id), quota: LIMITS.quota } }));

route('POST', '/me', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { name: V.opt(NAME), notifyOpen: V.opt(V.bool()) });
  if (b.name !== undefined) {
    const name = cleanText(b.name);
    if (!name) fail(400, 'Please enter your name.');
    run('UPDATE users SET name = ? WHERE id = ?', name, ctx.user.id);
  }
  if (b.notifyOpen !== undefined) run('UPDATE users SET notify_open = ? WHERE id = ?', b.notifyOpen ? 1 : 0, ctx.user.id);
  return { account: account(get('SELECT * FROM users WHERE id = ?', ctx.user.id)) };
});

route('GET', '/sessions', 'user', (ctx) => ({
  sessions: all('SELECT token_hash, label, created_at AS createdAt, last_seen AS lastSeen FROM sessions WHERE user_id = ? ORDER BY last_seen DESC', ctx.user.id)
    .map(({ token_hash, ...s }) => ({ ...s, current: token_hash === ctx.session.token_hash })),
}));

route('POST', '/sessions/logout-others', 'user', (ctx) => {
  run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', ctx.user.id, ctx.session.token_hash);
  run('DELETE FROM devices WHERE user_id = ?', ctx.user.id);
  logEvent(ctx.user.id, 'logout_everywhere');
  return { ok: true };
});

route('POST', '/account/password', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32, kdfSalt: V.b64(16), newAuthKey: KEY32, vaultByPw: VAULT_BLOB });
  await requirePassword(ctx, b.authKey);
  const auth = await hashSecret(b.newAuthKey);
  tx(() => {
    run('UPDATE users SET kdf_salt = ?, auth_salt = ?, auth_hash = ?, vault_by_pw = ? WHERE id = ?',
      b.kdfSalt, auth.salt, auth.hash, b.vaultByPw, ctx.user.id);
    run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', ctx.user.id, ctx.session.token_hash);
    run('DELETE FROM devices WHERE user_id = ?', ctx.user.id);
  });
  logEvent(ctx.user.id, 'password_changed', { notify: true });
  sendMail(ctx.user.email, 'Your VaultSpace password was changed',
    'Your password was changed and your other devices were logged out. If this was not you, reset it with your recovery key now.');
  return { ok: true };
});

route('POST', '/account/recovery-key', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32 });
  await requirePassword(ctx, b.authKey);
  logEvent(ctx.user.id, 'recovery_key_viewed', { notify: true });
  return { rkByVault: ctx.user.rk_by_vault };
});

route('POST', '/account/delete', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32 });
  await requirePassword(ctx, b.authKey);
  const files = all('SELECT id FROM files WHERE owner_id = ?', ctx.user.id);
  tx(() => {
    run('DELETE FROM events WHERE user_id = ?', ctx.user.id);
    run('DELETE FROM users WHERE id = ?', ctx.user.id);   // cascades to files, shares, sessions, devices
  });
  files.forEach((f) => store.removeFile(f.id));
  return { ok: true };
});

// ---- two-factor authentication (TOTP, RFC 6238) -----------------------------------------
// Each code works once: we remember the last time step used, so a code seen over someone's
// shoulder cannot be replayed.
function checkTotp(u, sealed, code) {
  const secret = unbase32(unseal(sealed));
  const step = Math.floor(Date.now() / 30000);
  for (const s of [step - 1, step, step + 1]) {
    if (s > u.totp_last && sameText(totpAt(secret, s), code)) {
      run('UPDATE users SET totp_last = ? WHERE id = ?', s, u.id);
      return true;
    }
  }
  return false;
}

route('POST', '/account/2fa/setup', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32 });
  await requirePassword(ctx, b.authKey);
  if (ctx.user.totp_secret) fail(400, 'Two-factor authentication is already on.');
  const secret = base32(crypto.randomBytes(20));
  run('UPDATE users SET totp_pending = ? WHERE id = ?', seal(secret), ctx.user.id);
  return { secret, uri: `otpauth://totp/VaultSpace:${encodeURIComponent(ctx.user.email)}?secret=${secret}&issuer=VaultSpace` };
});

route('POST', '/account/2fa/enable', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { code: CODE });
  limit(`2fa:${ctx.user.id}`, 10, 900);
  if (!ctx.user.totp_pending) fail(400, 'Start the setup first.');
  if (!checkTotp(ctx.user, ctx.user.totp_pending, b.code)) fail(400, 'That code is incorrect. Check the time on your phone.');
  run('UPDATE users SET totp_secret = totp_pending, totp_pending = NULL WHERE id = ?', ctx.user.id);
  logEvent(ctx.user.id, '2fa_on', { notify: true });
  return { ok: true };
});

route('POST', '/account/2fa/disable', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { authKey: KEY32, code: CODE });
  await requirePassword(ctx, b.authKey);
  if (!ctx.user.totp_secret) fail(400, 'Two-factor authentication is not on.');
  if (!checkTotp(ctx.user, ctx.user.totp_secret, b.code)) fail(400, 'That code is incorrect.');
  run('UPDATE users SET totp_secret = NULL, totp_last = 0 WHERE id = ?', ctx.user.id);
  logEvent(ctx.user.id, '2fa_off', { notify: true });
  sendMail(ctx.user.email, 'Two-factor authentication was turned off', 'Two-factor authentication was turned off for your VaultSpace account. If this was not you, change your password now.');
  return { ok: true };
});

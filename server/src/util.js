// Small security helpers shared by the whole server.
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { SECRET } from './config.js';

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1 };
const DUMMY_SALT = crypto.randomBytes(16);

export const now = () => Math.floor(Date.now() / 1000);
export const ID_RE = /^[A-Za-z0-9_-]{22}$/;      // 16 random bytes, base64url
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;   // 32 random bytes, base64url
export const newId = () => crypto.randomBytes(16).toString('base64url');
export const newToken = () => crypto.randomBytes(32).toString('base64url');
export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('base64url');
export const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest();
export const sixDigits = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');

// Constant-time comparison, so response timing never hints at how much of a secret matched.
export function sameText(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Secrets the app sends us (authKey, recovery proof, passphrase proof) are stored only as scrypt hashes.
export async function hashSecret(b64) {
  const salt = crypto.randomBytes(16);
  return { salt, hash: await scrypt(Buffer.from(b64, 'base64url'), salt, 32, SCRYPT) };
}

// Always does the full scrypt work, even when the user does not exist, so timing
// cannot be used to discover which emails have accounts.
export async function checkSecret(b64, salt, hash) {
  const h = await scrypt(Buffer.from(b64, 'base64url'), salt ? Buffer.from(salt) : DUMMY_SALT, 32, SCRYPT);
  return !!hash && crypto.timingSafeEqual(h, Buffer.from(hash));
}

// True only for a valid P-256 public key in X.509 SPKI form (what the app generates).
export function isP256(b64) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64url'), format: 'der', type: 'spki' });
    return key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
  } catch {
    return false;
  }
}

// Strips control characters and invisible/bidi characters such as U+202E, which can make
// "fdp.exe" display as "exe.pdf".
export const cleanText = (s) =>
  s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁯﻿]/g, '').trim();

// AES-256-GCM with a key derived from the server secret (for two-factor secrets at rest).
const SEAL_KEY = Buffer.from(crypto.hkdfSync('sha256', SECRET, Buffer.alloc(0), 'vs-seal', 32));
export function seal(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', SEAL_KEY, iv);
  const body = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, body, c.getAuthTag()]).toString('base64url');
}
export function unseal(b64) {
  const buf = Buffer.from(b64, 'base64url');
  const d = crypto.createDecipheriv('aes-256-gcm', SEAL_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8');
}

// RFC 4648 base32, the format authenticator apps expect for TOTP secrets.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf) {
  let out = '', bits = 0, value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function unbase32(s) {
  const bytes = [];
  let bits = 0, value = 0;
  for (const ch of s) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}

// RFC 6238 time-based one-time password (HMAC-SHA1, 6 digits, 30 s steps).
export function totpAt(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', secret).update(msg).digest();
  const offset = h[h.length - 1] & 15;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

// Share state, computed the same way everywhere.
export function shareStatus(s, t = now()) {
  if (s.revoked_at) return 'revoked';
  if (s.expires_at <= t) return 'expired';
  if (s.pass_fails >= 5) return 'locked';
  if (s.opens_used >= s.max_opens) return 'used_up';
  return 'active';
}

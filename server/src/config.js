// Central configuration. Secrets come from the environment or the data directory,
// never from the source code, so the repository itself contains nothing sensitive.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const ROOT = path.resolve(import.meta.dirname, '..');
export const DATA_DIR = path.resolve(process.env.VS_DATA || path.join(ROOT, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

// 32 random bytes created on first start. Used for HMACs (fake salts, code hashes)
// and to encrypt two-factor secrets at rest.
function loadSecret() {
  const file = path.join(DATA_DIR, 'server.secret');
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32), { mode: 0o600 });
  return fs.readFileSync(file);
}

export const SECRET = loadSecret();
export const PROD = process.env.NODE_ENV === 'production';

export const config = {
  port: Number(process.env.PORT || 8443),
  host: process.env.HOST || '0.0.0.0',
  tlsKey: process.env.TLS_KEY || path.join(DATA_DIR, 'tls', 'key.pem'),
  tlsCert: process.env.TLS_CERT || path.join(DATA_DIR, 'tls', 'cert.pem'),
  devHttp: process.env.DEV_HTTP === '1' && !PROD,
  trustProxy: process.env.TRUST_PROXY === '1',
  smtp: process.env.SMTP_HOST ? {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
  } : null,
  // Alternative to SMTP when outgoing mail ports are blocked: Brevo's HTTPS email API.
  mailApi: process.env.BREVO_API_KEY ? { key: process.env.BREVO_API_KEY, from: process.env.MAIL_FROM } : null,
};

export const LIMITS = {
  chunk: 1024 * 1024,              // plaintext bytes per encrypted chunk
  maxFile: 50 * 1024 * 1024,       // per file
  quota: 250 * 1024 * 1024,        // per user, all versions included
  maxFiles: 200,
  maxVersions: 5,
  maxSharesPerFile: 50,
  kdfIters: 600_000,               // PBKDF2 iterations the app uses (OWASP 2023)
  sessionIdle: 30 * 60,
  sessionMax: 12 * 3600,
  openWindow: 5 * 60,              // how long one "open" lets the recipient download chunks
  codeTtl: 10 * 60,
};

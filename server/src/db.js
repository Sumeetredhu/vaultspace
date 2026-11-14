// SQLite storage using Node's built-in driver. Every query is a prepared statement with
// bound parameters, so user input can never change the SQL itself (no SQL injection).
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR } from './config.js';
import { now, sha256 } from './util.js';

export const db = new DatabaseSync(path.join(DATA_DIR, 'vaultspace.db'));

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL,
  kdf_salt TEXT NOT NULL, kdf_iters INTEGER NOT NULL,
  auth_salt BLOB NOT NULL, auth_hash BLOB NOT NULL,
  rk_salt BLOB NOT NULL, rk_hash BLOB NOT NULL,
  vault_by_pw TEXT NOT NULL, vault_by_rk TEXT NOT NULL, rk_by_vault TEXT NOT NULL,
  pub_key TEXT NOT NULL, priv_by_vault TEXT NOT NULL,
  totp_secret TEXT, totp_pending TEXT, totp_last INTEGER NOT NULL DEFAULT 0,
  notify_open INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS codes (
  purpose TEXT NOT NULL, email TEXT NOT NULL, hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (purpose, email)
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, label TEXT NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_by_vault TEXT, current_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE, version INTEGER NOT NULL,
  size INTEGER NOT NULL, chunks INTEGER NOT NULL, meta TEXT, uploaded_by TEXT,
  status TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (file_id, version)
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_email TEXT NOT NULL, perm TEXT NOT NULL, notify INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, max_opens INTEGER NOT NULL, opens_used INTEGER NOT NULL DEFAULT 0,
  eph_pub TEXT NOT NULL, wrapped_key TEXT NOT NULL,
  pass_salt TEXT, pass_auth_salt BLOB, pass_hash BLOB, pass_fails INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER, expired_logged INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS opens (
  token_hash TEXT PRIMARY KEY, share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  version INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, file_id TEXT, share_id TEXT,
  actor TEXT, type TEXT NOT NULL, at INTEGER NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_seq INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS shares_recipient ON shares(recipient_id);
CREATE INDEX IF NOT EXISTS shares_file ON shares(file_id);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, seq);
`);

const statements = new Map();
const prepared = (sql) => {
  let s = statements.get(sql);
  if (!s) statements.set(sql, (s = db.prepare(sql)));
  return s;
};
export const get = (sql, ...args) => prepared(sql).get(...args);
export const all = (sql, ...args) => prepared(sql).all(...args);
export const run = (sql, ...args) => prepared(sql).run(...args);

// Runs fn inside one transaction: either every write happens or none does. fn must be synchronous.
export function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

// ---- tamper-evident activity log -------------------------------------------------
// Each user's events form a hash chain: every entry stores the hash of the one before it.
// Editing or deleting an old entry breaks every hash after it, which verifyChain detects.
const chainHash = (e) => sha256([e.prev, e.user_id, e.file_id, e.share_id, e.actor, e.type, e.at].join('|'));

export function logEvent(userId, type, { fileId = null, shareId = null, actor = null, notify = false } = {}) {
  const prev = get('SELECT hash FROM events WHERE user_id = ? ORDER BY seq DESC LIMIT 1', userId)?.hash ?? 'start';
  const e = { prev, user_id: userId, file_id: fileId, share_id: shareId, actor, type, at: now() };
  const { lastInsertRowid } = run(
    'INSERT INTO events (user_id, file_id, share_id, actor, type, at, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    userId, fileId, shareId, actor, type, e.at, prev, chainHash(e),
  );
  if (notify) run('INSERT INTO notifications (user_id, event_seq) VALUES (?, ?)', userId, lastInsertRowid);
}

export function verifyChain(userId) {
  let prev = 'start', count = 0;
  for (const e of all('SELECT * FROM events WHERE user_id = ? ORDER BY seq', userId)) {
    if (e.prev !== prev || chainHash(e) !== e.hash) return { ok: false, count, brokenAt: e.seq };
    prev = e.hash;
    count++;
  }
  return { ok: true, count };
}

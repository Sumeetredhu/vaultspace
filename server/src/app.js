// Request pipeline: find route -> rate limit -> authenticate -> handler -> JSON response.
// Errors become short, generic messages; details stay in the server log with a reference id.
import crypto from 'node:crypto';
import { route, findRoute, send, limit, clientIp, HttpError } from './http.js';
import { authenticate } from './auth.js';
import { all, run, logEvent } from './db.js';
import * as store from './storage.js';
import { LIMITS } from './config.js';
import { now } from './util.js';
import './files.js';
import './shares.js';
import './activity.js';

route('GET', '/health', 'public', () => ({ service: 'VaultSpace', ok: true }));

export async function handle(req, res) {
  const ref = crypto.randomBytes(4).toString('hex');
  const ip = clientIp(req), t0 = Date.now();
  // Access log for diagnosing problems: method, path without the query string, status, time, IP.
  // Never bodies, headers or tokens. Odd characters are replaced so a path can't forge log lines.
  if (!process.env.QUIET) res.on('finish', () => {
    const safe = (s, n) => String(s).slice(0, n).replace(/[^\x21-\x7e]/g, '?');
    console.log(`${safe(req.method, 10)} ${safe(req.url.split('?')[0], 120)} ${res.statusCode} ${Date.now() - t0}ms ${safe(ip, 45)}`);
  });
  try {
    const url = new URL(req.url, 'https://vaultspace.local');
    limit(`ip:${ip}`, 1500, 60);
    const { route: r, params } = findRoute(req.method, url.pathname);
    const ctx = { req, res, ip, params, query: url.searchParams };
    if (r.auth === 'user') authenticate(ctx);
    const out = await r.handler(ctx);
    if (!res.headersSent) send(res, 200, out ?? { ok: true });
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (e instanceof HttpError) {
      send(res, e.status, { error: e.message, ...e.extra }, e.status === 413 ? { Connection: 'close' } : {});
    } else {
      console.error(`[${ref}]`, e);
      send(res, 500, { error: 'Something went wrong on our side. Please try again.', ref });
    }
  }
}

// Runs every minute: removes expired codes, sessions and viewing windows, abandoned uploads,
// and records "link expired" in the owner's history.
export function cleanup() {
  const t = now();
  run('DELETE FROM codes WHERE expires_at < ?', t);
  run('DELETE FROM opens WHERE expires_at < ?', t);
  run('DELETE FROM sessions WHERE last_seen < ? OR created_at < ?', t - LIMITS.sessionIdle, t - LIMITS.sessionMax);
  for (const v of all("SELECT file_id, version FROM versions WHERE status = 'uploading' AND created_at < ?", t - 3600)) {
    run('DELETE FROM versions WHERE file_id = ? AND version = ?', v.file_id, v.version);
    store.removeVersion(v.file_id, v.version);
  }
  for (const f of all('SELECT id FROM files WHERE current_version = 0 AND created_at < ?', t - 3600)) {
    run('DELETE FROM files WHERE id = ?', f.id);
    store.removeFile(f.id);
  }
  for (const s of all('SELECT * FROM shares WHERE expires_at <= ? AND expired_logged = 0 AND revoked_at IS NULL', t)) {
    run('UPDATE shares SET expired_logged = 1 WHERE id = ?', s.id);
    logEvent(s.owner_id, 'expired', { fileId: s.file_id, shareId: s.id, actor: s.recipient_email, notify: !!s.notify });
  }
}

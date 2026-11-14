// Sharing. The owner's app encrypts the file key for the recipient's public key, so only the
// recipient can unwrap it. The server enforces every rule the owner set (expiry, open limit,
// permission, passphrase attempts, revocation) on every request, so editing the app cannot bypass them.
import { LIMITS } from './config.js';
import { route, readJson, V, fail, limit } from './http.js';
import { get, all, run, tx, logEvent } from './db.js';
import { reserveVersion, receiveChunk, finishVersion, sendChunk } from './files.js';
import { now, newId, newToken, sha256, hashSecret, checkSecret, isP256, shareStatus, TOKEN_RE } from './util.js';

const REASONS = {
  revoked: 'The owner removed your access to this file.',
  expired: 'This share has expired.',
  used_up: 'You have used all the opens the owner allowed.',
  locked: 'This share was locked after too many wrong passphrases.',
};

// Looks up a share addressed to the logged-in user. Anyone else gets "not found".
const incoming = (ctx) =>
  get('SELECT * FROM shares WHERE id = ? AND recipient_id = ?', ctx.params.id, ctx.user.id) || fail(404, 'Share not found.');

function requireActive(s) {
  const status = shareStatus(s);
  if (status !== 'active') fail(403, REASONS[status], { status });
}

// ---- owner side --------------------------------------------------------------------
// Find the account (and its public key) behind an email address, so the app can encrypt for it.
route('GET', '/users/key', 'user', (ctx) => {
  limit(`lookup:${ctx.user.id}`, 60, 3600);
  const email = V.email()(ctx.query.get('email'), 'email');
  const u = get('SELECT id, name, email, pub_key FROM users WHERE email = ?', email);
  if (!u) fail(404, 'No VaultSpace account uses this email yet. Ask them to install VaultSpace and sign up, then share again.');
  if (u.id === ctx.user.id) fail(400, 'You cannot share a file with yourself.');
  return { userId: u.id, name: u.name, email: u.email, pubKey: u.pub_key };
});

route('POST', '/files/:id/shares', 'user', async (ctx) => {
  const f = get('SELECT * FROM files WHERE id = ? AND owner_id = ?', ctx.params.id, ctx.user.id) || fail(404, 'File not found.');
  const b = await readJson(ctx.req, {
    recipientId: V.str(22, 22, /^[A-Za-z0-9_-]{22}$/),
    perm: V.oneOf('view', 'download', 'edit'),
    expiresIn: V.int(600, 30 * 86400),       // 10 minutes to 30 days; the server computes the exact time
    maxOpens: V.int(1, 50),
    notify: V.bool(),
    ephPub: V.b64(91),                        // the sender's one-time public key (ECIES)
    wrappedKey: V.b64(60, 100),               // file key encrypted for the recipient
    pass: V.opt(V.obj({ salt: V.b64(16), auth: V.b64(32) })),
  });
  limit(`share:${ctx.user.id}`, 60, 3600);
  if (!f.current_version) fail(409, 'This file is still uploading.');
  if (!isP256(b.ephPub)) fail(400, 'Invalid key.');
  const r = get('SELECT id, email FROM users WHERE id = ?', b.recipientId) || fail(404, 'Recipient not found.');
  if (r.id === ctx.user.id) fail(400, 'You cannot share a file with yourself.');
  const t = now();
  const active = all('SELECT * FROM shares WHERE file_id = ?', f.id).filter((s) => shareStatus(s, t) === 'active');
  if (active.length >= LIMITS.maxSharesPerFile) fail(400, 'This file has too many active shares.');
  if (active.some((s) => s.recipient_id === r.id)) fail(409, `${r.email} already has access. Remove it first to change the rules.`);
  const pass = b.pass ? await hashSecret(b.pass.auth) : null;
  const id = newId();
  run(`INSERT INTO shares (id, file_id, owner_id, recipient_id, recipient_email, perm, notify, expires_at, max_opens,
       eph_pub, wrapped_key, pass_salt, pass_auth_salt, pass_hash, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  id, f.id, ctx.user.id, r.id, r.email, b.perm, b.notify ? 1 : 0, t + b.expiresIn, b.maxOpens,
  b.ephPub, b.wrappedKey, b.pass?.salt ?? null, pass?.salt ?? null, pass?.hash ?? null, t);
  logEvent(ctx.user.id, 'share', { fileId: f.id, shareId: id, actor: r.email });
  logEvent(r.id, 'received', { fileId: f.id, shareId: id, actor: ctx.user.email, notify: true });
  return { id, expiresAt: t + b.expiresIn };
});

route('GET', '/shares/out', 'user', (ctx) => {
  const t = now();
  return {
    shares: all('SELECT * FROM shares WHERE owner_id = ? AND created_at > ? ORDER BY created_at DESC', ctx.user.id, t - 30 * 86400)
      .map((s) => ({
        id: s.id, fileId: s.file_id, email: s.recipient_email, perm: s.perm, expiresAt: s.expires_at,
        maxOpens: s.max_opens, opensUsed: s.opens_used, hasPass: !!s.pass_hash, createdAt: s.created_at, status: shareStatus(s, t),
      })),
  };
});

// Revoking takes effect immediately: the share and any open viewing windows stop working at once.
route('DELETE', '/shares/:id', 'user', (ctx) => {
  const s = get('SELECT * FROM shares WHERE id = ? AND owner_id = ?', ctx.params.id, ctx.user.id) || fail(404, 'Share not found.');
  if (!s.revoked_at) {
    tx(() => {
      run('UPDATE shares SET revoked_at = ? WHERE id = ?', now(), s.id);
      run('DELETE FROM opens WHERE share_id = ?', s.id);
    });
    logEvent(ctx.user.id, 'revoke', { fileId: s.file_id, shareId: s.id, actor: s.recipient_email });
  }
  return { ok: true };
});

// "Stop all sharing": for one file, or for the whole vault when no fileId is given.
route('POST', '/shares/revoke-all', 'user', async (ctx) => {
  const { fileId } = await readJson(ctx.req, { fileId: V.opt(V.str(22, 22, /^[A-Za-z0-9_-]{22}$/)) });
  const t = now();
  const n = tx(() => {
    const target = all('SELECT id FROM shares WHERE owner_id = ? AND revoked_at IS NULL AND expires_at > ? AND (? IS NULL OR file_id = ?)',
      ctx.user.id, t, fileId ?? null, fileId ?? null);
    for (const s of target) {
      run('UPDATE shares SET revoked_at = ? WHERE id = ?', t, s.id);
      run('DELETE FROM opens WHERE share_id = ?', s.id);
    }
    return target.length;
  });
  logEvent(ctx.user.id, 'revoke_all', { fileId: fileId ?? null, actor: String(n) });
  return { revoked: n };
});

// ---- recipient side ------------------------------------------------------------------
// Passphrase-protected shares hide the wrapped key and the file name until the passphrase is
// checked by the server; otherwise the passphrase could be guessed offline with no attempt limit.
route('GET', '/shares/in', 'user', (ctx) => {
  const t = now();
  const rows = all(`
    SELECT s.*, u.name AS owner_name, u.email AS owner_email, v.meta, v.size
    FROM shares s JOIN users u ON u.id = s.owner_id
    JOIN files f ON f.id = s.file_id JOIN versions v ON v.file_id = f.id AND v.version = f.current_version
    WHERE s.recipient_id = ? AND s.created_at > ? ORDER BY s.created_at DESC`, ctx.user.id, t - 30 * 86400);
  return {
    shares: rows.map((s) => {
      const status = shareStatus(s, t);
      const reveal = status === 'active' && !s.pass_hash;
      return {
        id: s.id, fileId: s.file_id, from: { name: s.owner_name, email: s.owner_email }, perm: s.perm,
        expiresAt: s.expires_at, maxOpens: s.max_opens, opensUsed: s.opens_used, status, size: s.size,
        hasPass: !!s.pass_hash, passSalt: s.pass_salt, createdAt: s.created_at,
        meta: reveal ? s.meta : null, ephPub: reveal ? s.eph_pub : null, wrappedKey: reveal ? s.wrapped_key : null,
      };
    }),
  };
});

// Opening counts against the limit. The count is a single conditional UPDATE, so even 20
// parallel requests on a 1-open share can only succeed once (no race condition).
route('POST', '/shares/:id/open', 'user', async (ctx) => {
  const b = await readJson(ctx.req, { passAuth: V.opt(V.b64(32)) });
  limit(`open:${ctx.user.id}`, 120, 3600);
  const s = incoming(ctx);
  requireActive(s);
  if (s.pass_hash) {
    if (!b.passAuth) fail(403, 'This file is protected with a passphrase.', { needPass: true });
    // Reserve the attempt *before* checking, so parallel guesses cannot exceed 5 in total.
    if (run('UPDATE shares SET pass_fails = pass_fails + 1 WHERE id = ? AND pass_fails < 5', s.id).changes !== 1) fail(403, REASONS.locked);
    if (!(await checkSecret(b.passAuth, s.pass_auth_salt, s.pass_hash))) {
      const left = 5 - get('SELECT pass_fails FROM shares WHERE id = ?', s.id).pass_fails;
      logEvent(s.owner_id, left > 0 ? 'pass_failed' : 'pass_locked', { fileId: s.file_id, shareId: s.id, actor: ctx.user.email, notify: left === 0 });
      fail(403, left > 0 ? `Wrong passphrase. ${left} ${left === 1 ? 'try' : 'tries'} left.` : 'Wrong passphrase. This share is now locked.', { needPass: left > 0 });
    }
    run('UPDATE shares SET pass_fails = 0 WHERE id = ?', s.id);
  }
  const t = now();
  const counted = run(`UPDATE shares SET opens_used = opens_used + 1 WHERE id = ? AND revoked_at IS NULL
                       AND expires_at > ? AND opens_used < max_opens AND pass_fails < 5`, s.id, t);
  if (counted.changes !== 1) fail(403, 'This file is no longer available to you.');
  const f = get('SELECT current_version FROM files WHERE id = ?', s.file_id);
  const v = get('SELECT * FROM versions WHERE file_id = ? AND version = ?', s.file_id, f.current_version);
  const token = newToken();
  run('INSERT INTO opens (token_hash, share_id, version, expires_at) VALUES (?, ?, ?, ?)', sha256(token), s.id, v.version, t + LIMITS.openWindow);
  const opensUsed = get('SELECT opens_used FROM shares WHERE id = ?', s.id).opens_used;
  logEvent(s.owner_id, 'open', { fileId: s.file_id, shareId: s.id, actor: ctx.user.email, notify: !!s.notify });
  if (opensUsed === s.max_opens) logEvent(s.owner_id, 'limit_reached', { fileId: s.file_id, shareId: s.id, actor: ctx.user.email });
  return {
    openToken: token, version: v.version, chunks: v.chunks, size: v.size, meta: v.meta, perm: s.perm,
    ephPub: s.eph_pub, wrappedKey: s.wrapped_key, opensLeft: s.max_opens - opensUsed, windowSeconds: LIMITS.openWindow,
  };
});

// A short "viewing window" created by /open. Checked again on every chunk, so revoking or
// expiry cuts off a download that is already in progress.
function openWindow(ctx) {
  const token = String(ctx.req.headers['x-open-token'] || '');
  if (!TOKEN_RE.test(token)) fail(403, 'Open the file again.');
  const o = get(`SELECT o.version AS open_version, o.expires_at AS open_until, s.*
                 FROM opens o JOIN shares s ON s.id = o.share_id
                 WHERE o.token_hash = ? AND s.id = ? AND s.recipient_id = ?`, sha256(token), ctx.params.id, ctx.user.id);
  if (!o || o.open_until < now()) fail(403, 'Your viewing window ended. Open the file again.');
  if (o.revoked_at || o.expires_at <= now()) fail(403, o.revoked_at ? REASONS.revoked : REASONS.expired);
  return o;
}

route('GET', '/shares/:id/chunk/:idx#', 'user', (ctx) => {
  const o = openWindow(ctx);
  sendChunk(ctx, o.file_id, o.open_version);
});

// The app calls this before saving a copy to the phone. View-only shares are refused here,
// and every allowed download is recorded in the owner's history.
route('POST', '/shares/:id/download', 'user', (ctx) => {
  const o = openWindow(ctx);
  if (o.perm === 'view') fail(403, 'The owner allowed viewing only.');
  logEvent(o.owner_id, 'download', { fileId: o.file_id, shareId: o.id, actor: ctx.user.email, notify: !!o.notify });
  return { ok: true };
});

// ---- "Can update" permission: recipient uploads a new version -----------------------------
function editable(ctx) {
  const s = incoming(ctx);
  if (s.perm !== 'edit') fail(403, 'The owner did not allow updates.');
  if (s.revoked_at || s.expires_at <= now()) fail(403, s.revoked_at ? REASONS.revoked : REASONS.expired);
  return s;
}

route('POST', '/shares/:id/versions', 'user', async (ctx) => {
  const { size } = await readJson(ctx.req, { size: V.int(0, LIMITS.maxFile) });
  const s = editable(ctx);
  limit(`upload:${ctx.user.id}`, 60, 3600);
  return reserveVersion(s.file_id, s.owner_id, ctx.user.id, size);
});

route('PUT', '/shares/:id/v/:ver#/:idx#', 'user', (ctx) => receiveChunk(ctx, editable(ctx).file_id, ctx.params.ver, ctx.user.id));

route('POST', '/shares/:id/v/:ver#/commit', 'user', async (ctx) => {
  const { meta } = await readJson(ctx.req, { meta: V.b64(29, 4096) });
  const s = editable(ctx);
  finishVersion(s.file_id, ctx.params.ver, ctx.user.id, meta);
  logEvent(s.owner_id, 'edited', { fileId: s.file_id, shareId: s.id, actor: ctx.user.email, notify: true });
  return { ok: true };
});

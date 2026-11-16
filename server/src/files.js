// Encrypted file storage. Files arrive already encrypted in 1 MiB chunks. The server checks
// ownership, sizes and quotas, and never sees file names, types or contents.
import { LIMITS } from './config.js';
import { route, readJson, readBody, V, fail, limit, send } from './http.js';
import { get, all, run, tx, logEvent } from './db.js';
import * as store from './storage.js';
import { now, newId, shareStatus } from './util.js';

const META = V.b64(29, 4096);   // file name/type/category, encrypted with the file key
const TAG = 28;                 // per chunk: 12-byte nonce + 16-byte GCM tag

export const chunkCount = (size) => Math.max(1, Math.ceil(size / LIMITS.chunk));
// Exact length every encrypted chunk must have, so nobody can store extra data past their quota.
const chunkLength = (v, i) => (i < v.chunks - 1 ? LIMITS.chunk : v.size - LIMITS.chunk * (v.chunks - 1)) + TAG;

const used = (ownerId) =>
  get('SELECT COALESCE(SUM(v.size), 0) AS n FROM versions v JOIN files f ON f.id = v.file_id WHERE f.owner_id = ?', ownerId).n;

// Starts a new version (the first upload, or a later edit). Quota is charged to the owner.
// Each person may have only one unfinished upload per file, so nobody (e.g. a recipient with
// "Can update") can fill the owner's quota with abandoned uploads.
export function reserveVersion(fileId, ownerId, uploaderId, size) {
  for (const v of all("SELECT version FROM versions WHERE file_id = ? AND uploaded_by = ? AND status = 'uploading'", fileId, uploaderId)) {
    run('DELETE FROM versions WHERE file_id = ? AND version = ?', fileId, v.version);
    store.removeVersion(fileId, v.version);
  }
  if (used(ownerId) + size > LIMITS.quota) fail(413, 'Not enough space left in the vault.');
  const version = (get('SELECT MAX(version) AS v FROM versions WHERE file_id = ?', fileId).v ?? 0) + 1;
  run("INSERT INTO versions (file_id, version, size, chunks, uploaded_by, status, created_at) VALUES (?, ?, ?, ?, ?, 'uploading', ?)",
    fileId, version, size, chunkCount(size), uploaderId, now());
  return { version, chunks: chunkCount(size) };
}

function openUpload(fileId, version, uploaderId) {
  const v = get('SELECT * FROM versions WHERE file_id = ? AND version = ?', fileId, version);
  if (!v || v.status !== 'uploading' || v.uploaded_by !== uploaderId) fail(409, 'This upload is not open.');
  return v;
}

// Each person may send only a few chunks at once. Every chunk in flight is held in memory
// (up to 1 MiB), so this stops one account from exhausting the server's memory.
const inFlight = new Map();
const MAX_IN_FLIGHT = 4;

export async function receiveChunk(ctx, fileId, version, uploaderId) {
  const v = openUpload(fileId, version, uploaderId);
  const i = ctx.params.idx;
  if (i >= v.chunks) fail(400, 'Invalid chunk number.');
  const busy = inFlight.get(uploaderId) || 0;
  if (busy >= MAX_IN_FLIGHT) fail(429, 'Too many uploads at once. Please wait a moment and try again.');
  inFlight.set(uploaderId, busy + 1);
  try {
    const body = await readBody(ctx.req, chunkLength(v, i));
    if (body.length !== chunkLength(v, i)) fail(400, 'Chunk has the wrong size.');
    // Check again: the upload may have been committed or cancelled while this body was arriving,
    // and a late chunk must never change a finished version or land in a reused version number.
    openUpload(fileId, version, uploaderId);
    store.writeChunk(fileId, version, i, body);
    return { ok: true };
  } finally {
    const left = inFlight.get(uploaderId) - 1;
    if (left > 0) inFlight.set(uploaderId, left);
    else inFlight.delete(uploaderId);
  }
}

// Marks a version complete once every chunk is present, makes it current, and keeps only the newest versions.
export function finishVersion(fileId, version, uploaderId, meta, keyByVault) {
  const v = openUpload(fileId, version, uploaderId);
  for (let i = 0; i < v.chunks; i++) if (!store.hasChunk(fileId, version, i)) fail(409, 'Upload is incomplete.');
  const pruned = tx(() => {
    run("UPDATE versions SET status = 'ready', meta = ? WHERE file_id = ? AND version = ?", meta, fileId, version);
    run('UPDATE files SET current_version = ?, updated_at = ? WHERE id = ?', version, now(), fileId);
    if (keyByVault) run('UPDATE files SET key_by_vault = ? WHERE id = ? AND key_by_vault IS NULL', keyByVault, fileId);
    // Old versions are pruned, but the owner's newest upload is always kept, so someone with
    // "Can update" can't wipe the owner's original by uploading several versions in a row.
    const ownerLatest = get(`SELECT MAX(v.version) AS n FROM versions v JOIN files f ON f.id = v.file_id
                             WHERE v.file_id = ? AND v.status = 'ready' AND v.uploaded_by = f.owner_id`, fileId).n;
    const old = all("SELECT version FROM versions WHERE file_id = ? AND status = 'ready' ORDER BY version DESC LIMIT -1 OFFSET ?", fileId, LIMITS.maxVersions)
      .filter((o) => o.version !== ownerLatest);
    for (const o of old) run('DELETE FROM versions WHERE file_id = ? AND version = ?', fileId, o.version);
    return old;
  });
  pruned.forEach((o) => store.removeVersion(fileId, o.version));
}

export function sendChunk(ctx, fileId, version) {
  const v = get("SELECT * FROM versions WHERE file_id = ? AND version = ? AND status = 'ready'", fileId, version);
  if (!v || ctx.params.idx >= v.chunks) fail(404, 'Not found.');
  const data = store.readChunk(fileId, version, ctx.params.idx) || fail(404, 'File data is missing.');
  send(ctx.res, 200, data);
}

// Ownership is checked inside the query itself. Someone else's file gets the same 404 as a
// file that does not exist, so ids reveal nothing.
const ownedFile = (ctx) =>
  get('SELECT * FROM files WHERE id = ? AND owner_id = ?', ctx.params.id, ctx.user.id) || fail(404, 'File not found.');

// ---- routes ---------------------------------------------------------------------------
route('GET', '/files', 'user', (ctx) => {
  const t = now();
  const files = all(`
    SELECT f.id, f.key_by_vault AS keyByVault, f.current_version AS version, v.size, v.meta,
           f.created_at AS createdAt, f.updated_at AS updatedAt,
           (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id AND s.revoked_at IS NULL AND s.expires_at > ?
              AND s.opens_used < s.max_opens AND s.pass_fails < 5) AS activeShares
    FROM files f JOIN versions v ON v.file_id = f.id AND v.version = f.current_version
    WHERE f.owner_id = ? ORDER BY f.updated_at DESC`, t, ctx.user.id);
  return { files, used: used(ctx.user.id), quota: LIMITS.quota };
});

route('POST', '/files', 'user', async (ctx) => {
  const { size } = await readJson(ctx.req, { size: V.int(0, LIMITS.maxFile) });
  limit(`upload:${ctx.user.id}`, 60, 3600);
  if (get('SELECT COUNT(*) AS n FROM files WHERE owner_id = ?', ctx.user.id).n >= LIMITS.maxFiles) fail(400, 'Your vault is full. Delete some files first.');
  if (used(ctx.user.id) + size > LIMITS.quota) fail(413, 'Not enough space left in the vault.');
  const id = newId();
  run('INSERT INTO files (id, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?)', id, ctx.user.id, now(), now());
  return { id, ...reserveVersion(id, ctx.user.id, ctx.user.id, size) };
});

route('PUT', '/files/:id/v/:ver#/:idx#', 'user', (ctx) => receiveChunk(ctx, ownedFile(ctx).id, ctx.params.ver, ctx.user.id));

route('POST', '/files/:id/v/:ver#/commit', 'user', async (ctx) => {
  const f = ownedFile(ctx);
  const b = await readJson(ctx.req, { meta: META, keyByVault: V.opt(V.b64(60)) });
  if (!f.key_by_vault && !b.keyByVault) fail(400, 'Missing file key.');
  finishVersion(f.id, ctx.params.ver, ctx.user.id, b.meta, b.keyByVault);
  logEvent(ctx.user.id, ctx.params.ver === 1 ? 'upload' : 'new_version', { fileId: f.id });
  return { ok: true };
});

route('GET', '/files/:id', 'user', (ctx) => {
  const f = ownedFile(ctx);
  const t = now();
  return {
    id: f.id, keyByVault: f.key_by_vault, version: f.current_version, createdAt: f.created_at, updatedAt: f.updated_at,
    versions: all(`SELECT v.version, v.size, v.meta, v.created_at AS createdAt, u.email AS uploadedBy
                   FROM versions v LEFT JOIN users u ON u.id = v.uploaded_by
                   WHERE v.file_id = ? AND v.status = 'ready' ORDER BY v.version DESC`, f.id),
    shares: all('SELECT * FROM shares WHERE file_id = ? ORDER BY created_at DESC', f.id).map((s) => ({
      id: s.id, email: s.recipient_email, perm: s.perm, expiresAt: s.expires_at, maxOpens: s.max_opens,
      opensUsed: s.opens_used, hasPass: !!s.pass_hash, createdAt: s.created_at, status: shareStatus(s, t),
    })),
  };
});

route('GET', '/files/:id/v/:ver#/:idx#', 'user', (ctx) => sendChunk(ctx, ownedFile(ctx).id, ctx.params.ver));

// Rename or change category: replaces the encrypted metadata of the current version.
route('POST', '/files/:id/meta', 'user', async (ctx) => {
  const f = ownedFile(ctx);
  const { meta } = await readJson(ctx.req, { meta: META });
  run('UPDATE versions SET meta = ? WHERE file_id = ? AND version = ?', meta, f.id, f.current_version);
  return { ok: true };
});

route('POST', '/files/:id/restore', 'user', async (ctx) => {
  const f = ownedFile(ctx);
  const { version } = await readJson(ctx.req, { version: V.int(1, 999999) });
  if (!get("SELECT 1 FROM versions WHERE file_id = ? AND version = ? AND status = 'ready'", f.id, version)) fail(404, 'Version not found.');
  run('UPDATE files SET current_version = ?, updated_at = ? WHERE id = ?', version, now(), f.id);
  logEvent(ctx.user.id, 'restore', { fileId: f.id, actor: `v${version}` });
  return { ok: true };
});

// Deleting removes every version and every share. The file key disappears with the row,
// so any leftover ciphertext could never be decrypted again ("crypto-shredding").
route('DELETE', '/files/:id', 'user', (ctx) => {
  const f = ownedFile(ctx);
  run('DELETE FROM files WHERE id = ?', f.id);
  store.removeFile(f.id);
  logEvent(ctx.user.id, 'delete', { fileId: f.id });
  return { ok: true };
});

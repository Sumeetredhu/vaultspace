// End-to-end tests of the API, focused on the security rules. Run with: npm test
// The "client" here sends random bytes where the app would send ciphertext; the server
// never decrypts anything, so that is enough to test every rule it enforces.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';

process.env.VS_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-test-'));
process.env.QUIET = '1';
process.env.TRUST_PROXY = '1';   // lets each simulated user come from its own IP
const { handle } = await import('../src/app.js');
const { outbox } = await import('../src/mail.js');
const { totpAt } = await import('../src/util.js');
const { run } = await import('../src/db.js');

const server = http.createServer(handle);
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

async function api(method, p, { body, token, headers = {}, raw } = {}) {
  const res = await fetch(base + p, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const json = (res.headers.get('content-type') || '').includes('json');
  return { status: res.status, headers: res.headers, data: json ? await res.json() : Buffer.from(await res.arrayBuffer()) };
}
const rand = (n) => crypto.randomBytes(n).toString('base64url');
const p256 = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const lastCode = (email) => /(\d{6})/.exec(outbox.filter((m) => m.to === email).at(-1).text)[1];
let counter = 0;
const freshEmail = () => `user${++counter}.${Date.now()}@example.com`;

async function signup(email = freshEmail()) {
  const headers = { 'x-forwarded-for': `10.0.${counter % 250}.${(counter * 7) % 250}` };
  await api('POST', '/auth/signup/start', { body: { email }, headers });
  const authKey = rand(32), rkAuth = rand(32);
  const r = await api('POST', '/auth/signup/finish', {
    headers,
    body: { email, code: lastCode(email), name: 'Test User', kdfSalt: rand(16), authKey, vaultByPw: rand(60),
      vaultByRk: rand(60), rkAuth, rkByVault: rand(48), pubKey: p256(), privByVault: rand(100) },
  });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return { email, authKey, rkAuth, token: r.data.token, id: r.data.account.id };
}

async function upload(user, size = 1500) {
  const r = await api('POST', '/files', { token: user.token, body: { size } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const n = r.data.chunks;
  for (let i = 0; i < n; i++) {
    const len = (i < n - 1 ? 1048576 : size - 1048576 * (n - 1)) + 28;
    const c = await api('PUT', `/files/${r.data.id}/v/1/${i}`, { token: user.token, raw: crypto.randomBytes(len) });
    assert.equal(c.status, 200);
  }
  const c = await api('POST', `/files/${r.data.id}/v/1/commit`, { token: user.token, body: { meta: rand(64), keyByVault: rand(60) } });
  assert.equal(c.status, 200);
  return r.data.id;
}

async function share(owner, fileId, recipient, extra = {}) {
  const k = await api('GET', `/users/key?email=${encodeURIComponent(recipient.email)}`, { token: owner.token });
  return api('POST', `/files/${fileId}/shares`, {
    token: owner.token,
    body: { recipientId: k.data.userId, perm: 'view', expiresIn: 3600, maxOpens: 2, notify: true, ephPub: p256(), wrappedKey: rand(60), ...extra },
  });
}

test('security headers on every response, chunks served as sandboxed attachments', async () => {
  const r = await api('GET', '/health');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(r.headers.get('x-powered-by'), null);
  const a = await signup();
  const id = await upload(a);
  const c = await api('GET', `/files/${id}/v/1/0`, { token: a.token });
  assert.equal(c.headers.get('content-type'), 'application/octet-stream');
  assert.equal(c.headers.get('content-disposition'), 'attachment');
  assert.match(c.headers.get('content-security-policy'), /sandbox/);
});

test('input validation: unknown fields, __proto__, bad types, oversized bodies', async () => {
  const email = freshEmail();
  assert.equal((await api('POST', '/auth/signup/start', { body: { email, admin: true } })).status, 400);
  assert.equal((await api('POST', '/auth/prelogin', { raw: '{"email":"a@b.co","__proto__":{"x":1}}', headers: { 'content-type': 'application/json' } })).status, 400);
  assert.equal((await api('POST', '/auth/prelogin', { body: { email: 'not-an-email' } })).status, 400);
  assert.equal((await api('POST', '/auth/prelogin', { body: { email: ['a@b.co'] } })).status, 400);
  assert.equal((await api('POST', '/auth/prelogin', { raw: `{"email":"${'a'.repeat(70000)}"}`, headers: { 'content-type': 'application/json' } })).status, 413);
  assert.equal((await api('GET', '/files/../../etc/passwd')).status, 404);
  assert.equal((await api('GET', '/nope')).status, 404);
});

test('no account enumeration: prelogin, login and signup look identical', async () => {
  const a = await signup();
  const ghost = freshEmail();
  const p1 = await api('POST', '/auth/prelogin', { body: { email: ghost } });
  const p2 = await api('POST', '/auth/prelogin', { body: { email: ghost } });
  assert.equal(p1.data.salt, p2.data.salt, 'fake salt must be stable');
  assert.equal(Buffer.from(p1.data.salt, 'base64url').length, 16);
  const wrongReal = await api('POST', '/auth/login', { body: { email: a.email, authKey: rand(32) } });
  const wrongGhost = await api('POST', '/auth/login', { body: { email: ghost, authKey: rand(32) } });
  assert.equal(wrongReal.status, 401);
  assert.deepEqual(wrongReal.data, wrongGhost.data);
  const s1 = await api('POST', '/auth/signup/start', { body: { email: a.email } });
  const s2 = await api('POST', '/auth/signup/start', { body: { email: freshEmail() } });
  assert.deepEqual(s1.data, s2.data);
});

test('login works, sessions end on logout, garbage tokens are rejected', async () => {
  const a = await signup();
  const r = await api('POST', '/auth/login', { body: { email: a.email, authKey: a.authKey }, headers: { 'x-device': 'Test phone' } });
  assert.equal(r.status, 200);
  assert.ok(r.data.keys.vaultByPw);
  assert.equal((await api('GET', '/me', { token: r.data.token })).status, 200);
  await api('POST', '/auth/logout', { token: r.data.token });
  assert.equal((await api('GET', '/me', { token: r.data.token })).status, 401);
  assert.equal((await api('GET', '/me', { token: 'x'.repeat(43) })).status, 401);
  assert.equal((await api('GET', '/me')).status, 401);
});

test('email codes die after 5 wrong guesses', async () => {
  const email = freshEmail();
  await api('POST', '/auth/signup/start', { body: { email } });
  const body = (code) => ({ email, code, name: 'X', kdfSalt: rand(16), authKey: rand(32), vaultByPw: rand(60), vaultByRk: rand(60), rkAuth: rand(32), rkByVault: rand(48), pubKey: p256(), privByVault: rand(100) });
  const real = lastCode(email);
  const wrong = real === '000000' ? '111111' : '000000';
  for (let i = 0; i < 5; i++) assert.equal((await api('POST', '/auth/signup/finish', { body: body(wrong) })).status, 400);
  const r = await api('POST', '/auth/signup/finish', { body: body(real) });
  assert.equal(r.status, 400, 'even the right code must fail after 5 wrong tries');
});

test('access control: other users cannot see, download or delete my files', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  for (const [m, p] of [['GET', `/files/${id}`], ['GET', `/files/${id}/v/1/0`], ['DELETE', `/files/${id}`], ['POST', `/files/${id}/restore`]]) {
    const r = await api(m, p, { token: b.token, ...(m === 'POST' ? { body: { version: 1 } } : {}) });
    assert.equal(r.status, 404, `${m} ${p} should be hidden`);
  }
  assert.equal((await api('GET', '/files', { token: b.token })).data.files.length, 0);
  assert.equal((await api('GET', `/files/${id}`, { token: a.token })).status, 200);
});

test('uploads: exact chunk sizes and quota are enforced', async () => {
  const a = await signup();
  const r = await api('POST', '/files', { token: a.token, body: { size: 100 } });
  assert.equal((await api('PUT', `/files/${r.data.id}/v/1/0`, { token: a.token, raw: crypto.randomBytes(500) })).status, 413);
  assert.equal((await api('PUT', `/files/${r.data.id}/v/1/0`, { token: a.token, raw: crypto.randomBytes(50) })).status, 400);
  assert.equal((await api('POST', `/files/${r.data.id}/v/1/commit`, { token: a.token, body: { meta: rand(64), keyByVault: rand(60) } })).status, 409);
  assert.equal((await api('POST', '/files', { token: a.token, body: { size: 60 * 1024 * 1024 } })).status, 400);
});

test('sharing: open limit holds even under 20 parallel opens', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  const s = await share(a, id, b, { maxOpens: 1 });
  assert.equal(s.status, 200, JSON.stringify(s.data));
  const results = await Promise.all(Array.from({ length: 20 }, () => api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: {} })));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  const list = await api('GET', '/shares/in', { token: b.token });
  assert.equal(list.data.shares[0].status, 'used_up');
});

test('sharing: recipient can view, cannot download view-only, loses access on revoke', async () => {
  const a = await signup(), b = await signup(), c = await signup();
  const id = await upload(a);
  const s = await share(a, id, b);
  const open = await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: {} });
  assert.equal(open.status, 200);
  const hdr = { 'x-open-token': open.data.openToken };
  assert.equal((await api('GET', `/shares/${s.data.id}/chunk/0`, { token: b.token, headers: hdr })).status, 200);
  assert.equal((await api('GET', `/shares/${s.data.id}/chunk/0`, { token: c.token, headers: hdr })).status, 403, 'a stolen open token is useless to someone else');
  assert.equal((await api('POST', `/shares/${s.data.id}/open`, { token: c.token, body: {} })).status, 404);
  assert.equal((await api('POST', `/shares/${s.data.id}/download`, { token: b.token, headers: hdr })).status, 403);
  assert.equal((await api('DELETE', `/shares/${s.data.id}`, { token: b.token })).status, 404, 'recipient cannot revoke');
  assert.equal((await api('DELETE', `/shares/${s.data.id}`, { token: a.token })).status, 200);
  assert.equal((await api('GET', `/shares/${s.data.id}/chunk/0`, { token: b.token, headers: hdr })).status, 403, 'revoke cuts an open window');
  assert.equal((await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: {} })).status, 403);
});

test('sharing: expired shares stop working (server clock)', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  const s = await share(a, id, b);
  run('UPDATE shares SET expires_at = ? WHERE id = ?', Math.floor(Date.now() / 1000) - 1, s.data.id);
  const r = await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: {} });
  assert.equal(r.status, 403);
  assert.equal(r.data.status, 'expired');
});

test('sharing: bad rules are rejected', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  assert.equal((await share(a, id, b, { maxOpens: 0 })).status, 400);
  assert.equal((await share(a, id, b, { maxOpens: 1.5 })).status, 400);
  assert.equal((await share(a, id, b, { expiresIn: -5 })).status, 400);
  assert.equal((await share(a, id, b, { perm: 'owner' })).status, 400);
  assert.equal((await share(a, id, b, { ephPub: rand(91) })).status, 400, 'garbage public keys are refused');
  assert.equal((await api('GET', `/users/key?email=${encodeURIComponent(a.email)}`, { token: a.token })).status, 400, 'no sharing with yourself');
});

test('passphrase: hidden key until checked, locks after 5 parallel wrong guesses', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  const passAuth = rand(32);
  const s = await share(a, id, b, { pass: { salt: rand(16), auth: passAuth }, maxOpens: 5 });
  const listed = (await api('GET', '/shares/in', { token: b.token })).data.shares[0];
  assert.equal(listed.wrappedKey, null);
  assert.equal(listed.meta, null);
  assert.equal((await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: {} })).data.needPass, true);
  const ok = await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: { passAuth } });
  assert.equal(ok.status, 200);
  assert.ok(ok.data.wrappedKey);
  await Promise.all(Array.from({ length: 12 }, () => api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: { passAuth: rand(32) } })));
  const after = await api('POST', `/shares/${s.data.id}/open`, { token: b.token, body: { passAuth } });
  assert.equal(after.status, 403, 'locked even for the right passphrase');
  assert.equal(after.data.status, 'locked');
});

test('"Can update" permission: only edit shares can upload a new version', async () => {
  const a = await signup(), b = await signup(), c = await signup();
  const id = await upload(a);
  const view = await share(a, id, b);
  assert.equal((await api('POST', `/shares/${view.data.id}/versions`, { token: b.token, body: { size: 10 } })).status, 403);
  const edit = await share(a, id, c, { perm: 'edit' });
  const v = await api('POST', `/shares/${edit.data.id}/versions`, { token: c.token, body: { size: 10 } });
  assert.equal(v.data.version, 2);
  await api('PUT', `/shares/${edit.data.id}/v/2/0`, { token: c.token, raw: crypto.randomBytes(38) });
  assert.equal((await api('POST', `/shares/${edit.data.id}/v/2/commit`, { token: c.token, body: { meta: rand(64) } })).status, 200);
  const f = await api('GET', `/files/${id}`, { token: a.token });
  assert.equal(f.data.version, 2);
  assert.equal(f.data.versions[0].uploadedBy, c.email);
  // abandoned uploads do not pile up against the owner's quota
  for (let i = 0; i < 5; i++) await api('POST', `/shares/${edit.data.id}/versions`, { token: c.token, body: { size: 40 * 1024 * 1024 } });
  const me = await api('GET', '/me', { token: a.token });
  assert.ok(me.data.usage.used < 41 * 1024 * 1024, `quota abuse: ${me.data.usage.used}`);
});

test('recovery needs both the email code and the recovery key, and logs out everywhere', async () => {
  const a = await signup();
  await api('POST', '/auth/recover/start', { body: { email: a.email } });
  const bad = await api('POST', '/auth/recover/verify', { body: { email: a.email, code: lastCode(a.email), rkAuth: rand(32) } });
  assert.equal(bad.status, 400);
  await api('POST', '/auth/recover/start', { body: { email: a.email } });
  const ok = await api('POST', '/auth/recover/verify', { body: { email: a.email, code: lastCode(a.email), rkAuth: a.rkAuth } });
  assert.equal(ok.status, 200);
  const done = await api('POST', '/auth/recover/finish', {
    body: { email: a.email, ticket: ok.data.ticket, kdfSalt: rand(16), authKey: rand(32), vaultByPw: rand(60), rkAuth: rand(32), vaultByRk: rand(60), rkByVault: rand(48) },
  });
  assert.equal(done.status, 200);
  assert.equal((await api('GET', '/me', { token: a.token })).status, 401, 'old session is gone');
});

test('TOTP matches the RFC 6238 test vector', () => {
  // Secret "12345678901234567890", T = 59 s -> step 1 -> 94287082 (8 digits) -> 287082 (6 digits)
  assert.equal(totpAt(Buffer.from('12345678901234567890'), 1), '287082');
});

test('activity log is hash-chained and detects tampering', async () => {
  const a = await signup(), b = await signup();
  const id = await upload(a);
  await share(a, id, b);
  assert.equal((await api('GET', '/history/verify', { token: a.token })).data.ok, true);
  run("UPDATE events SET actor = 'someone-else@example.com' WHERE user_id = ? AND type = 'share'", a.id);
  assert.equal((await api('GET', '/history/verify', { token: a.token })).data.ok, false);
  const n = await api('GET', '/notifications', { token: b.token });
  assert.ok(n.data.items.some((x) => x.type === 'received'));
});

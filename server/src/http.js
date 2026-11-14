// A small HTTP toolkit written for VaultSpace: routing, request size limits, strict JSON
// validation, rate limiting and security headers. Nothing in here trusts the client.
import { config } from './config.js';

export class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}
export const fail = (status, message, extra) => { throw new HttpError(status, message, extra); };

// ---- routing -----------------------------------------------------------------
// Every route must say who may call it. There is no default, so nothing becomes public by accident.
// In patterns, ":name" matches a 22-character random id and ":name#" matches a small number.
const routes = [];
export function route(method, pattern, auth, handler) {
  if (auth !== 'public' && auth !== 'user') throw new Error(`Route ${pattern} must declare 'public' or 'user'`);
  const params = [];
  const source = pattern.replace(/:(\w+)(#?)/g, (_, name, numeric) => {
    params.push([name, numeric === '#']);
    return numeric ? '(\\d{1,6})' : '([A-Za-z0-9_-]{22})';
  });
  routes.push({ method, re: new RegExp(`^${source}$`), params, auth, handler });
}

export function findRoute(method, path) {
  let pathExists = false;
  for (const r of routes) {
    const m = r.re.exec(path);
    if (!m) continue;
    pathExists = true;
    if (r.method !== method) continue;
    const params = {};
    r.params.forEach(([name, numeric], i) => { params[name] = numeric ? Number(m[i + 1]) : m[i + 1]; });
    return { route: r, params };
  }
  return fail(pathExists ? 405 : 404, pathExists ? 'Method not allowed.' : 'Not found.');
}

// ---- responses ---------------------------------------------------------------
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

// Binary bodies (encrypted chunks) are always sent as an attachment inside a sandbox, so even
// bytes crafted to look like HTML can never run as a web page on our origin.
export function send(res, status, body, headers = {}) {
  const binary = Buffer.isBuffer(body);
  const data = binary ? body : JSON.stringify(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': binary ? 'application/octet-stream' : 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    ...(binary ? { 'Content-Disposition': 'attachment', 'Content-Security-Policy': "default-src 'none'; sandbox" } : {}),
    ...headers,
  });
  res.end(data);
}

// ---- request bodies ----------------------------------------------------------
// Counts bytes as they arrive and stops at the limit, instead of trusting Content-Length.
export function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    if (Number(req.headers['content-length'] || 0) > limit) return reject(new HttpError(413, 'Request too large.'));
    const parts = [];
    let size = 0, done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > limit) {
        done = true;
        req.pause();
        return reject(new HttpError(413, 'Request too large.'));
      }
      parts.push(chunk);
    });
    req.on('end', () => { if (!done) resolve(Buffer.concat(parts)); });
    req.on('error', reject);
  });
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export async function readJson(req, schema) {
  if (!String(req.headers['content-type'] || '').startsWith('application/json')) fail(415, 'Expected JSON.');
  const raw = await readBody(req, 64 * 1024);
  let obj;
  try {
    obj = JSON.parse(raw.toString('utf8'), (k, v) => {
      if (FORBIDDEN_KEYS.has(k)) throw new Error('forbidden key');
      return v;
    });
  } catch {
    fail(400, 'Invalid JSON.');
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) fail(400, 'Invalid JSON.');
  return check(obj, schema);
}

// ---- validation --------------------------------------------------------------
// Each validator returns the clean value or rejects the request. Unknown fields are rejected too,
// so a client can never set server-owned fields like owner_id or opens_used ("mass assignment").
const EMAIL_RE = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,24}$/;
const bad = (k) => fail(400, `Invalid ${String(k).slice(0, 40)}.`);

export const V = {
  str: (min, max, re) => (v, k) =>
    typeof v === 'string' && v.length >= min && v.length <= max && (!re || re.test(v)) ? v : bad(k),
  int: (min, max) => (v, k) => (Number.isInteger(v) && v >= min && v <= max ? v : bad(k)),
  bool: () => (v, k) => (typeof v === 'boolean' ? v : bad(k)),
  oneOf: (...options) => (v, k) => (options.includes(v) ? v : bad(k)),
  b64: (min, max = min) => (v, k) => {
    if (typeof v !== 'string' || v.length > Math.ceil((max * 4) / 3) || !/^[A-Za-z0-9_-]*$/.test(v)) bad(k);
    const n = Buffer.from(v, 'base64url').length;
    return n >= min && n <= max ? v : bad(k);
  },
  email: () => (v, k) => {
    if (typeof v !== 'string' || v.length > 254) bad(k);
    const e = v.trim().toLowerCase();
    return EMAIL_RE.test(e) ? e : bad(k);
  },
  obj: (schema) => (v, k) => (v && typeof v === 'object' && !Array.isArray(v) ? check(v, schema) : bad(k)),
  opt: (f) => (v, k) => (v === undefined || v === null ? undefined : f(v, k)),
};

export function check(obj, schema) {
  for (const k of Object.keys(obj)) if (!Object.hasOwn(schema, k)) fail(400, `Unexpected field ${k.slice(0, 40)}.`);
  const out = {};
  for (const [k, validate] of Object.entries(schema)) out[k] = validate(obj[k], k);
  return out;
}

// ---- rate limiting -----------------------------------------------------------
// Fixed-window counters kept in memory: limit("login:1.2.3.4", 30, 300) allows 30 calls per 5 minutes.
const buckets = new Map();
export function limit(key, max, windowSec) {
  const t = Date.now();
  let b = buckets.get(key);
  if (!b || t > b.reset) {
    if (buckets.size > 200_000) buckets.clear();   // memory guard against key flooding
    b = { n: 0, reset: t + windowSec * 1000 };
    buckets.set(key, b);
  }
  if (++b.n > max) fail(429, 'Too many requests. Please wait a moment and try again.', { retryAfter: Math.ceil((b.reset - t) / 1000) });
}
setInterval(() => {
  const t = Date.now();
  for (const [k, b] of buckets) if (t > b.reset) buckets.delete(k);
}, 60_000).unref();

// Only trust X-Forwarded-For when a local reverse proxy is explicitly configured; otherwise
// anyone could send a fake header to dodge per-IP rate limits.
export function clientIp(req) {
  const peer = req.socket.remoteAddress || '';
  if (config.trustProxy && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer)) {
    const hop = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim();
    if (hop) return hop;
  }
  return peer;
}

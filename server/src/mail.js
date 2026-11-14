// Sends plain-text email through SMTP over TLS (port 465). Our own minimal SMTP client,
// built on node:tls, so no mail library is needed.
import tls from 'node:tls';
import crypto from 'node:crypto';
import { config, PROD } from './config.js';

export const outbox = [];   // development only: lets local demos and tests read the codes

export function sendMail(to, subject, text) {
  if (/[\r\n]/.test(to + subject)) return;   // header-injection guard (addresses are validated anyway)
  if (config.mailApi) {
    mailApi(config.mailApi, to, subject, text).catch((e) => console.error('mail failed:', e.message));
    return;
  }
  if (!config.smtp) {
    if (PROD) return console.error('mail: SMTP is not configured, message dropped');
    outbox.push({ to, subject, text });
    if (!process.env.QUIET) console.log(`[dev-mail] to=${to} | ${subject}\n${text}\n`);
    return;
  }
  smtp(config.smtp, to, subject, text).catch((e) => console.error('mail failed:', e.message));
}

const b64 = (s) => Buffer.from(s).toString('base64');

// Brevo transactional email over HTTPS, using Node's built-in fetch (no SDK).
async function mailApi(cfg, to, subject, text) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': cfg.key, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: 'VaultSpace', email: cfg.from }, to: [{ email: to }], subject, textContent: text }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!r.ok) throw new Error(`mail API replied ${r.status}`);
}

function smtp(cfg, to, subject, text) {
  const message = [
    `From: VaultSpace <${cfg.from}>`,
    `To: <${to}>`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@vaultspace>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(text).replace(/.{76}/g, '$&\r\n'),   // base64 lines never start with ".", so no dot-stuffing needed
    '.',
  ].join('\r\n');

  // The conversation: [what we send, reply code we expect back]. null = just wait for the greeting.
  const steps = [
    [null, 220], ['EHLO vaultspace', 250], ['AUTH LOGIN', 334], [b64(cfg.user), 334], [b64(cfg.pass), 235],
    [`MAIL FROM:<${cfg.from}>`, 250], [`RCPT TO:<${to}>`, 250], ['DATA', 354], [message, 250],
  ];

  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host, minVersion: 'TLSv1.2' });
    sock.setTimeout(20_000, () => sock.destroy(new Error('SMTP timeout')));
    let buf = '', step = 0;
    sock.on('data', (d) => {
      buf += d;
      if (!buf.endsWith('\r\n')) return;
      const lines = buf.trimEnd().split('\r\n');
      const last = lines[lines.length - 1];
      if (!/^\d{3} /.test(last)) return;          // "250-..." means more lines are coming
      buf = '';
      const code = Number(last.slice(0, 3));
      if (code !== steps[step][1]) {
        sock.destroy();
        return reject(new Error(`SMTP replied ${code} at step ${step}`));
      }
      if (++step === steps.length) {
        sock.end('QUIT\r\n');
        return resolve();
      }
      sock.write(`${steps[step][0]}\r\n`);
    });
    sock.on('error', reject);
  });
}

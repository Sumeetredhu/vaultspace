// Tests our SMTP client against a fake mail server that behaves like Gmail, including the
// "221" goodbye after QUIT, which once crashed the server.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.VS_DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-mail-'));
const { smtp } = await import('../src/mail.js');

// A tiny SMTP server. `passwordOk` decides whether AUTH succeeds (235) or fails (535).
async function fakeServer(passwordOk) {
  const seen = [];
  const server = net.createServer((s) => {
    let buf = '', inData = false, authStep = 0;
    s.write('220 fake.smtp ready\r\n');
    s.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') { inData = false; s.write('250 2.0.0 queued\r\n'); }
          continue;
        }
        seen.push(line);
        if (line.startsWith('EHLO')) s.write('250-fake.smtp\r\n250-SIZE 35882577\r\n250 AUTH LOGIN PLAIN\r\n');
        else if (line === 'AUTH LOGIN') { authStep = 1; s.write('334 VXNlcm5hbWU6\r\n'); }
        else if (authStep === 1) { authStep = 2; s.write('334 UGFzc3dvcmQ6\r\n'); }
        else if (authStep === 2) { authStep = 0; s.write(passwordOk ? '235 2.7.0 Accepted\r\n' : '535 5.7.8 Bad credentials\r\n'); }
        else if (line.startsWith('MAIL FROM') || line.startsWith('RCPT TO')) s.write('250 2.1.0 OK\r\n');
        else if (line === 'DATA') { inData = true; s.write('354 Go ahead\r\n'); }
        else if (line === 'QUIT') { s.write('221 2.0.0 closing connection\r\n'); s.end(); }
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const connect = () => net.connect(server.address().port, '127.0.0.1');
  return { server, seen, connect };
}

const cfg = { host: 'fake.smtp', port: 465, user: 'sender@example.com', pass: 'app-password', from: 'sender@example.com' };

test('sends a message and survives the server goodbye after QUIT', async () => {
  const f = await fakeServer(true);
  await smtp(cfg, 'user@example.com', 'Your code', 'Your code is 123456', f.connect);
  await new Promise((r) => setTimeout(r, 100));   // let the "221" reply arrive; it must not throw
  assert.ok(f.seen.includes('RCPT TO:<user@example.com>'));
  assert.ok(f.seen.includes('QUIT'));
  f.server.close();
});

test('a rejected login (wrong App Password) is reported, not thrown', async () => {
  const f = await fakeServer(false);
  await assert.rejects(smtp(cfg, 'user@example.com', 'Your code', 'x', f.connect), /SMTP replied 535/);
  f.server.close();
});

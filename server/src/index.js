// Starts the HTTPS server. Plain HTTP is only allowed in development, and only on localhost.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { config } from './config.js';
import { handle, cleanup } from './app.js';

let server, scheme = 'https';
if (fs.existsSync(config.tlsKey) && fs.existsSync(config.tlsCert)) {
  server = https.createServer({ key: fs.readFileSync(config.tlsKey), cert: fs.readFileSync(config.tlsCert), minVersion: 'TLSv1.2' }, handle);
} else if (config.devHttp) {
  server = http.createServer(handle);
  config.host = '127.0.0.1';
  scheme = 'http';
  console.warn('DEVELOPMENT MODE: plain HTTP on localhost only.');
} else {
  console.error(`TLS certificate not found (${config.tlsCert}). Run scripts/make-cert.sh first.`);
  process.exit(1);
}

// Timeouts stop slow-loris style attacks from holding connections open forever.
server.headersTimeout = 15_000;
server.requestTimeout = 120_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 60;
server.maxConnections = 1000;   // caps memory and file handles if someone opens connections in bulk

server.listen(config.port, config.host, () => console.log(`VaultSpace server on ${scheme}://${config.host}:${config.port}`));
setInterval(() => { try { cleanup(); } catch (e) { console.error('cleanup failed', e); } }, 60_000);
cleanup();

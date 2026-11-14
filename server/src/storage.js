// Encrypted chunks on disk at data/blobs/<fileId>/<version>/<index>.
// Paths are built only from server-generated ids and integers, checked here again,
// so no client input can ever point outside the blob folder (no path traversal).
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from './config.js';
import { ID_RE } from './util.js';

const ROOT = path.join(DATA_DIR, 'blobs');
fs.mkdirSync(ROOT, { recursive: true, mode: 0o700 });

function dir(fileId, version) {
  if (!ID_RE.test(fileId) || (version !== undefined && !Number.isInteger(version))) throw new Error('bad blob path');
  return version === undefined ? path.join(ROOT, fileId) : path.join(ROOT, fileId, String(version));
}
const chunkPath = (fileId, version, i) => {
  if (!Number.isInteger(i)) throw new Error('bad blob path');
  return path.join(dir(fileId, version), String(i));
};

export function writeChunk(fileId, version, i, data) {
  fs.mkdirSync(dir(fileId, version), { recursive: true, mode: 0o700 });
  const target = chunkPath(fileId, version, i);
  fs.writeFileSync(`${target}.tmp`, data, { mode: 0o600 });
  fs.renameSync(`${target}.tmp`, target);   // atomic: readers never see half a chunk
}

export const hasChunk = (fileId, version, i) => fs.existsSync(chunkPath(fileId, version, i));

export function readChunk(fileId, version, i) {
  try {
    return fs.readFileSync(chunkPath(fileId, version, i));
  } catch {
    return null;
  }
}

export const removeVersion = (fileId, version) => fs.rmSync(dir(fileId, version), { recursive: true, force: true });
export const removeFile = (fileId) => fs.rmSync(dir(fileId), { recursive: true, force: true });

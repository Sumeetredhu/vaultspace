// Access history and in-app notifications. Only the owner of a history can read it,
// and nothing here lets a client write events: the server records them itself.
import { route } from './http.js';
import { get, all, run, verifyChain } from './db.js';

route('GET', '/history', 'user', (ctx) => ({
  events: all(`SELECT seq, type, file_id AS fileId, share_id AS shareId, actor, at
               FROM events WHERE user_id = ? ORDER BY seq DESC LIMIT 300`, ctx.user.id),
}));

route('GET', '/history/verify', 'user', (ctx) => verifyChain(ctx.user.id));

route('GET', '/notifications', 'user', (ctx) => ({
  items: all(`SELECT n.id, n.read, e.type, e.file_id AS fileId, e.actor, e.at
              FROM notifications n JOIN events e ON e.seq = n.event_seq
              WHERE n.user_id = ? ORDER BY n.id DESC LIMIT 100`, ctx.user.id),
  unread: get('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0', ctx.user.id).n,
}));

route('POST', '/notifications/read', 'user', (ctx) => {
  run('UPDATE notifications SET read = 1 WHERE user_id = ?', ctx.user.id);
  return { ok: true };
});

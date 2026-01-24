import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import { WebSocketServer } from 'ws';

const app = express();
const PORT = process.env.PORT || 3001;

const dataDir = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'tictactoe.db');
const db = new sqlite3.Database(dbPath);

const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

const all = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });

const initDb = async () => {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (from_user_id) REFERENCES users(id),
      FOREIGN KEY (to_user_id) REFERENCES users(id)
    )
  `);
};

app.use(express.json());
app.use(
  cors({
    origin: [/^http:\/\/localhost:4200$/, /^https?:\/\/.*$/],
    credentials: true,
  })
);

const createToken = () => crypto.randomBytes(24).toString('hex');
const nowIso = () => new Date().toISOString();

const socketsByUser = new Map();

const sendToUser = (userId, payload) => {
  const sockets = socketsByUser.get(userId);
  if (!sockets) return;
  const message = JSON.stringify(payload);
  sockets.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(message);
    }
  });
};

const requireAuth = async (req, res, next) => {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  const session = await get(
    'SELECT sessions.user_id, sessions.expires_at FROM sessions WHERE token = ?',
    [token]
  );
  if (!session) return res.status(401).json({ error: 'invalid_token' });
  if (new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'expired_token' });
  }

  req.userId = session.user_id;
  return next();
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  const normalized = String(username).trim().toLowerCase();
  if (normalized.length < 3) return res.status(400).json({ error: 'username_too_short' });
  if (String(password).length < 4) return res.status(400).json({ error: 'password_too_short' });

  try {
    const hash = await bcrypt.hash(String(password), 10);
    await run(
      'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
      [normalized, hash, nowIso()]
    );
    return res.json({ ok: true });
  } catch (err) {
    if (String(err.message || '').includes('UNIQUE')) {
      return res.status(409).json({ error: 'username_taken' });
    }
    return res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  const normalized = String(username).trim().toLowerCase();
  const user = await get(
    'SELECT id, password_hash FROM users WHERE username = ?',
    [normalized]
  );
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await bcrypt.compare(String(password), user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const token = createToken();
  const expires = new Date();
  expires.setDate(expires.getDate() + 7);

  await run(
    'INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)',
    [user.id, token, nowIso(), expires.toISOString()]
  );

  return res.json({ token });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await get('SELECT id, username FROM users WHERE id = ?', [req.userId]);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  return res.json({ id: user.id, username: user.username });
});

app.get('/api/users/search', requireAuth, async (req, res) => {
  const query = String(req.query.q || '').trim().toLowerCase();
  if (!query) return res.json({ users: [] });

  const limit = 10;
  const isId = /^\d+$/.test(query);
  const sql = isId
    ? 'SELECT id, username FROM users WHERE id = ? LIMIT ?'
    : 'SELECT id, username FROM users WHERE username LIKE ? ORDER BY username LIMIT ?';
  const params = isId ? [Number(query), limit] : [`%${query}%`, limit];

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'server_error' });
    return res.json({ users: rows || [] });
  });
});

app.post('/api/logout', requireAuth, async (req, res) => {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) {
    await run('DELETE FROM sessions WHERE token = ?', [token]);
  }
  return res.json({ ok: true });
});

app.get('/api/invites', requireAuth, async (req, res) => {
  const userId = req.userId;
  const rows = await all(
    `
    SELECT
      invites.id,
      invites.from_user_id,
      invites.to_user_id,
      invites.status,
      invites.created_at,
      fu.username AS from_username,
      tu.username AS to_username
    FROM invites
    JOIN users fu ON fu.id = invites.from_user_id
    JOIN users tu ON tu.id = invites.to_user_id
    WHERE (invites.from_user_id = ? OR invites.to_user_id = ?)
      AND invites.status = 'pending'
    ORDER BY invites.created_at DESC
    `,
    [userId, userId]
  );
  return res.json({ invites: rows });
});

app.post('/api/invites', requireAuth, async (req, res) => {
  const fromUserId = req.userId;
  const { toUserId } = req.body || {};
  if (!toUserId) return res.status(400).json({ error: 'missing_to_user' });
  if (Number(toUserId) === fromUserId) {
    return res.status(400).json({ error: 'cannot_invite_self' });
  }

  const target = await get('SELECT id FROM users WHERE id = ?', [Number(toUserId)]);
  if (!target) return res.status(404).json({ error: 'user_not_found' });

  const createdAt = nowIso();
  const result = await run(
    'INSERT INTO invites (from_user_id, to_user_id, status, created_at) VALUES (?, ?, ?, ?)',
    [fromUserId, Number(toUserId), 'pending', createdAt]
  );

  sendToUser(fromUserId, { type: 'invites:update' });
  sendToUser(Number(toUserId), { type: 'invites:update' });

  return res.json({ id: result.lastID, createdAt });
});

app.post('/api/invites/:id/cancel', requireAuth, async (req, res) => {
  const inviteId = Number(req.params.id);
  const invite = await get(
    'SELECT id, from_user_id, to_user_id, status FROM invites WHERE id = ?',
    [inviteId]
  );
  if (!invite) return res.status(404).json({ error: 'invite_not_found' });
  if (invite.from_user_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
  if (invite.status !== 'pending') return res.status(400).json({ error: 'not_pending' });

  await run('UPDATE invites SET status = ? WHERE id = ?', ['canceled', inviteId]);
  sendToUser(invite.from_user_id, { type: 'invites:update' });
  sendToUser(invite.to_user_id, { type: 'invites:update' });
  return res.json({ ok: true });
});

app.post('/api/invites/:id/accept', requireAuth, async (req, res) => {
  const inviteId = Number(req.params.id);
  const invite = await get(
    'SELECT id, from_user_id, to_user_id, status FROM invites WHERE id = ?',
    [inviteId]
  );
  if (!invite) return res.status(404).json({ error: 'invite_not_found' });
  if (invite.to_user_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
  if (invite.status !== 'pending') return res.status(400).json({ error: 'not_pending' });

  await run('UPDATE invites SET status = ? WHERE id = ?', ['accepted', inviteId]);
  sendToUser(invite.from_user_id, { type: 'invites:update' });
  sendToUser(invite.to_user_id, { type: 'invites:update' });
  return res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', async (ws, req) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    if (!token) {
      ws.close(1008, 'missing_token');
      return;
    }

    const session = await get(
      'SELECT sessions.user_id, sessions.expires_at FROM sessions WHERE token = ?',
      [token]
    );
    if (!session || new Date(session.expires_at) < new Date()) {
      ws.close(1008, 'invalid_token');
      return;
    }

    const userId = session.user_id;
    const set = socketsByUser.get(userId) || new Set();
    set.add(ws);
    socketsByUser.set(userId, set);

    ws.on('close', () => {
      const current = socketsByUser.get(userId);
      if (!current) return;
      current.delete(ws);
      if (current.size === 0) socketsByUser.delete(userId);
    });
  } catch (err) {
    ws.close(1011, 'server_error');
  }
});

initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`API listening on :${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to init DB', err);
    process.exit(1);
  });

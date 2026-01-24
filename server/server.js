import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';

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

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`API listening on :${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to init DB', err);
    process.exit(1);
  });

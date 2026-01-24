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
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);

  try {
    await run('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
  } catch {
    // ignore if column already exists
  }

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

  await run(`
    CREATE TABLE IF NOT EXISTS games (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_user_id INTEGER NOT NULL,
      guest_user_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      state_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (host_user_id) REFERENCES users(id),
      FOREIGN KEY (guest_user_id) REFERENCES users(id)
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

const passwordRules = {
  minLength: 8,
  hasLower: /[a-z]/,
  hasUpper: /[A-Z]/,
  hasSpecial: /[^A-Za-z0-9]/,
};

const getPasswordIssues = (password) => {
  const issues = [];
  if (String(password).length < passwordRules.minLength) issues.push('password_too_short');
  if (!passwordRules.hasLower.test(String(password))) issues.push('password_missing_lower');
  if (!passwordRules.hasUpper.test(String(password))) issues.push('password_missing_upper');
  if (!passwordRules.hasSpecial.test(String(password))) issues.push('password_missing_special');
  return issues;
};

const usernameRules = {
  minLength: 3,
  pattern: /^[a-z0-9_]+$/i,
  reserved: ['admin'],
};

const getUsernameIssue = (username) => {
  const normalized = String(username).trim().toLowerCase();
  if (normalized.length < usernameRules.minLength) return 'username_too_short';
  if (!usernameRules.pattern.test(normalized)) return 'username_invalid';
  if (usernameRules.reserved.includes(normalized)) return 'username_reserved';
  return null;
};

const createInitialState = (hostUserId) => ({
  boards: Array.from({ length: 9 }, () => Array(9).fill(null)),
  boardWinners: Array(9).fill(null),
  currentPlayerId: hostUserId,
  globalWinner: null,
  nextAllowedBoard: null,
});

const checkBoardWinner = (board) => {
  const lines = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6],
  ];

  for (const [a, b, c] of lines) {
    if (board[a] && board[a] === board[b] && board[a] === board[c]) {
      return board[a];
    }
  }

  if (board.every((c) => c !== null)) {
    return 'Draw';
  }

  return null;
};

const checkGlobalWinner = (boardWinners) => {
  const miniBoard = boardWinners.map((w) => (w === 'X' || w === 'O' ? w : null));
  const win = checkBoardWinner(miniBoard);

  if (win === 'Draw') {
    if (boardWinners.every((w) => w)) {
      return 'Draw';
    }
    return null;
  }

  return win;
};

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

const requireAdmin = async (req, res, next) => {
  const user = await get('SELECT is_admin FROM users WHERE id = ?', [req.userId]);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'forbidden' });
  return next();
};

const ensureAdminUser = async () => {
  const existingAdmin = await get('SELECT id FROM users WHERE is_admin = 1 LIMIT 1');
  if (existingAdmin) return;

  const adminUsername = String(process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || 'Admin!1234');

  const passwordIssues = getPasswordIssues(adminPassword);
  if (passwordIssues.length > 0) {
    console.warn('Admin password does not meet policy; admin user not created.');
    return;
  }

  const hash = await bcrypt.hash(adminPassword, 10);
  const existingUser = await get('SELECT id, is_admin FROM users WHERE username = ?', [adminUsername]);
  if (existingUser) {
    await run('UPDATE users SET is_admin = 1, password_hash = ? WHERE id = ?', [
      hash,
      existingUser.id,
    ]);
    console.log(`Admin user promoted: ${adminUsername}`);
    return;
  }

  try {
    await run(
      'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
      [adminUsername, hash, 1, nowIso()]
    );
    console.log(`Admin user created: ${adminUsername}`);
  } catch (err) {
    if (!String(err.message || '').includes('UNIQUE')) {
      console.error('Failed to create admin user', err);
    }
  }
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  const normalized = String(username).trim().toLowerCase();
  const usernameIssue = getUsernameIssue(username);
  if (usernameIssue) return res.status(400).json({ error: usernameIssue });

  const passwordIssues = getPasswordIssues(password);
  if (passwordIssues.length > 0) {
    return res.status(400).json({ error: 'password_invalid', details: passwordIssues });
  }

  try {
    const hash = await bcrypt.hash(String(password), 10);
    await run(
      'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
      [normalized, hash, 0, nowIso()]
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
    'SELECT id, password_hash, is_admin FROM users WHERE username = ?',
    [normalized]
  );
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  if (user.is_admin) return res.status(403).json({ error: 'admin_only' });

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

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  const normalized = String(username).trim().toLowerCase();
  const user = await get(
    'SELECT id, password_hash, is_admin FROM users WHERE username = ?',
    [normalized]
  );
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  if (!user.is_admin) return res.status(403).json({ error: 'admin_only' });

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
  const user = await get('SELECT id, username, is_admin FROM users WHERE id = ?', [req.userId]);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  return res.json({ id: user.id, username: user.username, isAdmin: !!user.is_admin });
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await all(
    'SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC'
  );
  return res.json({
    users: (users || []).map((user) => ({
      id: user.id,
      username: user.username,
      isAdmin: !!user.is_admin,
      createdAt: user.created_at,
    })),
  });
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const targetId = Number(req.params.id);
  if (!Number.isFinite(targetId)) return res.status(400).json({ error: 'invalid_user' });
  if (targetId === req.userId) return res.status(400).json({ error: 'cannot_delete_self' });

  const target = await get('SELECT id, is_admin FROM users WHERE id = ?', [targetId]);
  if (!target) return res.status(404).json({ error: 'user_not_found' });
  if (target.is_admin) return res.status(400).json({ error: 'cannot_delete_admin' });

  await run('DELETE FROM sessions WHERE user_id = ?', [targetId]);
  await run('DELETE FROM invites WHERE from_user_id = ? OR to_user_id = ?', [targetId, targetId]);
  await run('DELETE FROM games WHERE host_user_id = ? OR guest_user_id = ?', [targetId, targetId]);
  await run('DELETE FROM users WHERE id = ?', [targetId]);

  return res.json({ ok: true });
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

  const createdAt = nowIso();
  const state = createInitialState(invite.from_user_id);
  const result = await run(
    'INSERT INTO games (host_user_id, guest_user_id, status, state_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
    [
      invite.from_user_id,
      invite.to_user_id,
      'active',
      JSON.stringify(state),
      createdAt,
      createdAt,
    ]
  );

  sendToUser(invite.from_user_id, { type: 'invites:update' });
  sendToUser(invite.to_user_id, { type: 'invites:update' });
  sendToUser(invite.from_user_id, { type: 'game:update', gameId: result.lastID });
  sendToUser(invite.to_user_id, { type: 'game:update', gameId: result.lastID });

  return res.json({ gameId: result.lastID });
});

app.get('/api/games/:id', requireAuth, async (req, res) => {
  const gameId = Number(req.params.id);
  const game = await get(
    `
    SELECT
      games.id,
      games.host_user_id,
      games.guest_user_id,
      games.status,
      games.state_json,
      hu.username AS host_username,
      gu.username AS guest_username
    FROM games
    JOIN users hu ON hu.id = games.host_user_id
    JOIN users gu ON gu.id = games.guest_user_id
    WHERE games.id = ?
    `,
    [gameId]
  );
  if (!game) return res.status(404).json({ error: 'game_not_found' });
  if (game.host_user_id !== req.userId && game.guest_user_id !== req.userId) {
    return res.status(403).json({ error: 'forbidden' });
  }

  return res.json({
    id: game.id,
    host: { id: game.host_user_id, username: game.host_username },
    guest: { id: game.guest_user_id, username: game.guest_username },
    state: JSON.parse(game.state_json),
  });
});

app.get('/api/games', requireAuth, async (req, res) => {
  const userId = req.userId;
  const rows = await all(
    `
    SELECT
      games.id,
      games.status,
      games.updated_at,
      games.host_user_id,
      games.guest_user_id,
      hu.username AS host_username,
      gu.username AS guest_username
    FROM games
    JOIN users hu ON hu.id = games.host_user_id
    JOIN users gu ON gu.id = games.guest_user_id
    WHERE (games.host_user_id = ? OR games.guest_user_id = ?)
      AND games.status IN ('active', 'finished')
    ORDER BY games.updated_at DESC
    `,
    [userId, userId]
  );

  const games = rows.map((game) => ({
    id: game.id,
    status: game.status,
    updatedAt: game.updated_at,
    host: { id: game.host_user_id, username: game.host_username },
    guest: { id: game.guest_user_id, username: game.guest_username },
  }));

  return res.json({ games });
});

app.post('/api/games/:id/move', requireAuth, async (req, res) => {
  const gameId = Number(req.params.id);
  const { boardIndex, cellIndex } = req.body || {};
  if (!Number.isInteger(boardIndex) || !Number.isInteger(cellIndex)) {
    return res.status(400).json({ error: 'invalid_move' });
  }

  const game = await get(
    `
    SELECT
      games.id,
      games.host_user_id,
      games.guest_user_id,
      games.status,
      games.state_json,
      hu.username AS host_username,
      gu.username AS guest_username
    FROM games
    JOIN users hu ON hu.id = games.host_user_id
    JOIN users gu ON gu.id = games.guest_user_id
    WHERE games.id = ?
    `,
    [gameId]
  );
  if (!game) return res.status(404).json({ error: 'game_not_found' });
  if (game.host_user_id !== req.userId && game.guest_user_id !== req.userId) {
    return res.status(403).json({ error: 'forbidden' });
  }
  if (game.status !== 'active') return res.status(400).json({ error: 'game_inactive' });

  const state = JSON.parse(game.state_json);
  if (state.globalWinner) return res.status(400).json({ error: 'game_over' });
  if (state.currentPlayerId !== req.userId) return res.status(400).json({ error: 'not_your_turn' });

  if (state.nextAllowedBoard !== null && state.nextAllowedBoard !== boardIndex) {
    return res.status(400).json({ error: 'wrong_board' });
  }

  const board = state.boards[boardIndex];
  if (!board || board[cellIndex] !== null) {
    return res.status(400).json({ error: 'invalid_cell' });
  }

  const symbol = req.userId === game.host_user_id ? 'X' : 'O';
  board[cellIndex] = symbol;

  const localWin = checkBoardWinner(board);
  if (localWin) {
    state.boardWinners[boardIndex] = localWin;
  }

  state.globalWinner = checkGlobalWinner(state.boardWinners);

  if (!state.globalWinner) {
    const targetBoardIndex = cellIndex;
    const targetWinner = state.boardWinners[targetBoardIndex];
    const targetBoard = state.boards[targetBoardIndex];

    if (!targetWinner && targetBoard.some((cell) => cell === null)) {
      state.nextAllowedBoard = targetBoardIndex;
    } else {
      state.nextAllowedBoard = null;
    }

    state.currentPlayerId =
      state.currentPlayerId === game.host_user_id ? game.guest_user_id : game.host_user_id;
  }

  const updatedAt = nowIso();
  const newStatus = state.globalWinner ? 'finished' : 'active';
  await run(
    'UPDATE games SET state_json = ?, status = ?, updated_at = ? WHERE id = ?',
    [JSON.stringify(state), newStatus, updatedAt, gameId]
  );

  sendToUser(game.host_user_id, { type: 'game:update', gameId });
  sendToUser(game.guest_user_id, { type: 'game:update', gameId });

  return res.json({
    id: game.id,
    host: { id: game.host_user_id, username: game.host_username },
    guest: { id: game.guest_user_id, username: game.guest_username },
    state,
  });
});

app.delete('/api/games/:id', requireAuth, async (req, res) => {
  const gameId = Number(req.params.id);
  const game = await get(
    'SELECT id, host_user_id, guest_user_id FROM games WHERE id = ?',
    [gameId]
  );
  if (!game) return res.status(404).json({ error: 'game_not_found' });
  if (game.host_user_id !== req.userId && game.guest_user_id !== req.userId) {
    return res.status(403).json({ error: 'forbidden' });
  }

  await run('DELETE FROM games WHERE id = ?', [gameId]);
  sendToUser(game.host_user_id, { type: 'game:update', gameId });
  sendToUser(game.guest_user_id, { type: 'game:update', gameId });

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
    return ensureAdminUser();
  })
  .then(() => {
    server.listen(PORT, () => {
      console.log(`API listening on :${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to init DB', err);
    process.exit(1);
  });

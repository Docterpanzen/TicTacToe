# TicTacToe Server (Node + SQLite)

Minimal REST API + WebSocket server used by the Angular frontend.

## Overview
- Express API for auth, invites, games.
- SQLite persistence (file-based) in server/data/tictactoe.db.
- WebSockets for real-time updates on invites and games.

## Run
```bash
npm install
npm start
```
Server starts on http://localhost:3001.

## Database schema
- users: id, username, password_hash, created_at
- sessions: id, user_id, token, created_at, expires_at
- invites: id, from_user_id, to_user_id, status, created_at
- games: id, host_user_id, guest_user_id, status, state_json, created_at, updated_at

## Auth model
- Login returns a session token.
- Requests include Authorization: Bearer <token>.
- Sessions expire after 7 days.

## REST API
Auth
- POST /api/register
- POST /api/login
- GET /api/me
- POST /api/logout

Users
- GET /api/users/search?q=<id|name>

Invites
- GET /api/invites
- POST /api/invites
- POST /api/invites/:id/accept
- POST /api/invites/:id/cancel

Games
- GET /api/games
- GET /api/games/:id
- POST /api/games/:id/move
- DELETE /api/games/:id

## WebSocket
Endpoint
- ws://localhost:3001/ws?token=<session_token>

Events (server → client)
- invites:update
- game:update (includes gameId)

## Game state
State is stored as JSON in games.state_json and mirrors the local game rules:
- boards: 9 mini-boards with 9 cells each
- boardWinners: per-board winner or Draw
- currentPlayerId: user ID whose turn it is
- globalWinner: X | O | Draw | null
- nextAllowedBoard: forced board index or null

## Implementation notes
- Host player uses X, guest uses O.
- Turn validation and board rules are enforced server-side.
- WebSocket updates notify both players to refresh game data.

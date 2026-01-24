# Ultimate Tic‑Tac‑Toe

Standalone Angular 20 app with a lightweight Node.js + SQLite backend. It supports local play and a multiplayer lobby with invitations. Multiplayer games persist in SQLite and can be reopened later.

## Pages
- Local game: /local
- Login/Register: /login
- Lobby (invites + active games): /lobby
- Multiplayer match: /game/:id

## User management (current)
- Username/password registration and login.
- Session token stored in localStorage.
- Authenticated API calls use Authorization: Bearer <token>.
- Users are searchable by ID or username.

## Multiplayer flow (current)
- Invite another user from the lobby search.
- Invitee can accept; a game is created and appears under Active games.
- Game is opened only when you click Öffnen.
- Live updates use WebSockets for invite and game updates.

## Project layout
- Angular app: src/
- Backend: server/ (see server details in [server/README.md](server/README.md))

## Development
Frontend (Angular):
```bash
npm install
npm run start
```
The dev server uses proxy.conf.json to forward /api and /ws to the backend.

Backend (Node + SQLite):
```bash
cd server
npm install
npm start
```

## Notes
- The local game UI stays unchanged; multiplayer uses the same board layout but shows player names.
- Board highlight: green if it is your turn, yellow if it is not.

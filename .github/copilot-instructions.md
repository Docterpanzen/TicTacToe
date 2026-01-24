# Copilot instructions

## Project overview

- Angular 20 standalone app bootstrapped via `bootstrapApplication()` in [src/main.ts](src/main.ts).
- Root component `App` is standalone and renders the Ultimate Tic‑Tac‑Toe UI via `Tictactoe` in [src/app/app.ts](src/app/app.ts) and [src/app/tictactoe/tictactoe.ts](src/app/tictactoe/tictactoe.ts).
- No routes are defined yet; `routes` is an empty array in [src/app/app.routes.ts](src/app/app.routes.ts).

## Architecture and data flow

- All game state lives in `Tictactoe`: `boards` (9 mini‑boards), `boardWinners`, `currentPlayer`, `globalWinner`, and `nextAllowedBoard` (forced move target). See [src/app/tictactoe/tictactoe.ts](src/app/tictactoe/tictactoe.ts).
- UI is purely template‑driven: clicks call `handleCellClick()`, and template uses `NgFor`, `NgIf`, `NgClass` for rendering and highlighting active boards in [src/app/tictactoe/tictactoe.html](src/app/tictactoe/tictactoe.html).
- Game rules are enforced in `handleCellClick()` with helper checks `checkBoardWinner()` and `checkGlobalWinner()`; do not split state across services unless adding cross‑component logic.

## Styling and UI conventions

- Tailwind is enabled globally via directives in [src/styles.scss](src/styles.scss) and configured in [tailwind.config.js](tailwind.config.js).
- Component templates heavily use Tailwind utility classes for layout, gradients, and state; prefer keeping styling in HTML rather than adding component SCSS.
- UI strings are currently German (e.g., “Unentschieden”, “Nächstes Brett”); keep language consistent when adding text.

## Developer workflows

- Dev server: `npm run start` (runs `ng serve -o`) per [package.json](package.json).
- Build: `npm run build` per [package.json](package.json).
- Tests: Angular CLI defaults (`ng test`) are referenced in [README.md](README.md) and Karma is configured in dependencies.

## Project‑specific patterns

- Standalone components (`standalone: true`) are used instead of NgModules; add new components with standalone imports.
- `Tictactoe` is imported directly by `App`; if you add more screens, consider routing first and update [src/app/app.routes.ts](src/app/app.routes.ts).
- State is mutated in place for performance/clarity (e.g., `board[cellIndex] = ...`); maintain this style unless introducing immutable state on purpose.

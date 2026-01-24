import { Component } from '@angular/core';
import { NgFor, NgIf, NgClass, AsyncPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService, AuthUser, UserSummary } from '../services/auth.service';

type Player = 'X' | 'O';
type Cell = Player | null;
type BoardWinner = Player | 'Draw' | null;

@Component({
  selector: 'app-tictactoe',
  standalone: true,
  imports: [NgFor, NgIf, NgClass, AsyncPipe, FormsModule],
  templateUrl: './tictactoe.html',
  styleUrl: './tictactoe.scss',
})
export class Tictactoe {
  // 9 kleine Bretter mit jeweils 9 Feldern
  boards: Cell[][] = [];
  // Gewinner pro kleinem Brett
  boardWinners: BoardWinner[] = [];

  currentPlayer: Player = 'X';
  globalWinner: BoardWinner = null;

  /**
   * Wohin der nächste Spieler MUSS:
   * - null  => beliebiges Brett (z.B. wenn Zielbrett voll/gewonnen)
   * - 0..8  => Index des nächsten Bretts
   */
  nextAllowedBoard: number | null = null;

  lastMoveDescription = '';

  user$!: Observable<AuthUser | null>;
  searchQuery = '';
  searchResults: UserSummary[] = [];
  searchBusy = false;

  constructor(private auth: AuthService, private router: Router) {
    this.user$ = this.auth.user$;
    this.resetGame();
  }

  async logout(): Promise<void> {
    await this.auth.logout();
    await this.router.navigateByUrl('/login');
  }

  async goToLobby(): Promise<void> {
    await this.router.navigateByUrl('/lobby');
  }

  async goToLogin(): Promise<void> {
    await this.router.navigateByUrl('/login');
  }

  async searchUsers(): Promise<void> {
    this.searchBusy = true;
    try {
      this.searchResults = await this.auth.searchUsers(this.searchQuery);
    } finally {
      this.searchBusy = false;
    }
  }

  challenge(user: UserSummary): void {
    // Multiplayer not implemented yet; this is a placeholder for the flow.
    alert(`Herausforderung an ${user.username} (#${user.id}) wird bald unterstützt.`);
  }

  resetGame(): void {
    this.boards = Array.from({ length: 9 }, () =>
      Array<Cell>(9).fill(null)
    );
    this.boardWinners = Array<BoardWinner>(9).fill(null);
    this.currentPlayer = 'X';
    this.globalWinner = null;
    this.nextAllowedBoard = null;
    this.lastMoveDescription = '';
  }

  handleCellClick(boardIndex: number, cellIndex: number): void {
    if (this.globalWinner) return; // Spiel schon vorbei

    const boardWinner = this.boardWinners[boardIndex];
    if (boardWinner) return; // Brett schon entschieden

    // Falsches Brett gewählt?
    if (
      this.nextAllowedBoard !== null &&
      this.nextAllowedBoard !== boardIndex
    ) {
      return;
    }

    const board = this.boards[boardIndex];

    // Feld schon belegt?
    if (board[cellIndex] !== null) return;

    // Zug setzen
    board[cellIndex] = this.currentPlayer;

    // Kleines Brett auswerten
    const localWin = this.checkBoardWinner(board);
    if (localWin) {
      this.boardWinners[boardIndex] = localWin;
    }

    // Großes Brett auswerten (wer 3 kleine Bretter in Linie gewinnt)
    this.globalWinner = this.checkGlobalWinner();

    // Nächstes Zielbrett bestimmen (entspricht der Position des gesetzten Felds)
    if (!this.globalWinner) {
      const targetBoardIndex = cellIndex;
      const targetWinner = this.boardWinners[targetBoardIndex];
      const targetBoard = this.boards[targetBoardIndex];

      // Wenn Zielbrett noch spielbar ist → dort muss der nächste Zug hin
      if (!targetWinner && targetBoard.some((cell) => cell === null)) {
        this.nextAllowedBoard = targetBoardIndex;
      } else {
        // Ansonsten freie Brettwahl
        this.nextAllowedBoard = null;
      }

      this.lastMoveDescription =
        `Spieler ${this.currentPlayer} auf Brett ${boardIndex + 1}, Feld ${
          cellIndex + 1
        }. ` +
        `Nächstes Brett: ${
          this.nextAllowedBoard === null ? 'frei wählbar' : this.nextAllowedBoard + 1
        }`;

      // Spieler wechseln
      this.currentPlayer = this.currentPlayer === 'X' ? 'O' : 'X';
    }
  }

  // Gewinner eines 3x3-Bretts bestimmen
  private checkBoardWinner(board: Cell[]): BoardWinner {
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
  }

  // Gewinner des großen Spielfelds aus den 9 kleinen Brett-Gewinnern berechnen
  private checkGlobalWinner(): BoardWinner {
    // Nur echte Spieler-Gewinne zählen für das große Brett, Draw wird wie leer behandelt
    const miniBoard: Cell[] = this.boardWinners.map((w) =>
      w === 'X' || w === 'O' ? w : null
    );

    const win = this.checkBoardWinner(miniBoard);

    if (win === 'Draw') {
      // Globales Unentschieden nur, wenn wirklich alle Bretter fertig sind
      if (this.boardWinners.every((w) => w)) {
        return 'Draw';
      }
      return null;
    }

    return win;
  }

  // UI: Markiert, welche Bretter aktuell „aktiv“ sind
  isBoardActive(index: number): boolean {
    if (this.globalWinner) return false;

    if (this.nextAllowedBoard === null) {
      // Alle noch spielbaren Bretter sind "aktiv"
      return (
        !this.boardWinners[index] &&
        this.boards[index].some((cell) => cell === null)
      );
    }

    return this.nextAllowedBoard === index;
  }
}

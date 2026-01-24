import { Component, DestroyRef, OnInit } from '@angular/core';
import { NgFor, NgIf, NgClass, AsyncPipe } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Observable } from 'rxjs';
import { AuthService, AuthUser } from '../services/auth.service';
import { GameResponse, GameService, BoardWinner } from '../services/game.service';
import { WsService } from '../services/ws.service';

@Component({
  selector: 'app-game',
  standalone: true,
  imports: [NgFor, NgIf, NgClass, AsyncPipe],
  templateUrl: './game.html',
})
export class GameComponent implements OnInit {
  user$!: Observable<AuthUser | null>;
  currentUser: AuthUser | null = null;
  game: GameResponse | null = null;
  loading = true;
  busy = false;

  constructor(
    private auth: AuthService,
    private gameService: GameService,
    private ws: WsService,
    private route: ActivatedRoute,
    private router: Router,
    private destroyRef: DestroyRef
  ) {
    this.user$ = this.auth.user$;
  }

  ngOnInit(): void {
    this.user$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((user) => {
        this.currentUser = user;
        if (!user) {
          void this.router.navigateByUrl('/login');
          return;
        }
        if (!this.auth.token) return;
        this.connectSocket(this.auth.token);
      });

    this.route.paramMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const id = Number(params.get('id'));
        if (!Number.isFinite(id)) {
          void this.router.navigateByUrl('/local');
          return;
        }
        void this.loadGame(id);
      });
  }

  async loadGame(gameId: number): Promise<void> {
    this.loading = true;
    try {
      this.game = await this.gameService.getGame(gameId);
    } finally {
      this.loading = false;
    }
  }

  async makeMove(boardIndex: number, cellIndex: number): Promise<void> {
    if (!this.game || !this.currentUser || this.busy) return;
    if (!this.isMyTurn()) return;

    this.busy = true;
    try {
      this.game = await this.gameService.makeMove(this.game.id, boardIndex, cellIndex);
    } finally {
      this.busy = false;
    }
  }

  async goToLobby(): Promise<void> {
    await this.router.navigateByUrl('/lobby');
  }

  async goToLocal(): Promise<void> {
    await this.router.navigateByUrl('/local');
  }

  isBoardActive(index: number): boolean {
    if (!this.game) return false;
    if (this.game.state.globalWinner) return false;

    if (this.game.state.nextAllowedBoard === null) {
      return (
        !this.game.state.boardWinners[index] &&
        this.game.state.boards[index].some((cell) => cell === null)
      );
    }

    return this.game.state.nextAllowedBoard === index;
  }

  isMyTurn(): boolean {
    if (!this.game || !this.currentUser) return false;
    return this.game.state.currentPlayerId === this.currentUser.id;
  }

  currentPlayerName(): string {
    if (!this.game) return '';
    return this.game.state.currentPlayerId === this.game.host.id
      ? this.game.host.username
      : this.game.guest.username;
  }

  winnerName(): string {
    if (!this.game) return '';
    const winner = this.game.state.globalWinner;
    if (winner === 'Draw') return 'Unentschieden';
    if (winner === 'X') return this.game.host.username;
    if (winner === 'O') return this.game.guest.username;
    return '';
  }

  boardWinnerName(winner: BoardWinner): string {
    if (!this.game) return '';
    if (winner === 'X') return this.game.host.username;
    if (winner === 'O') return this.game.guest.username;
    return 'Unentschieden';
  }

  private connectSocket(token: string): void {
    this.ws
      .connect(token)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((msg) => {
        if (msg?.type === 'game:update' && this.game && msg.gameId === this.game.id) {
          void this.loadGame(this.game.id);
        }
      });
  }
}

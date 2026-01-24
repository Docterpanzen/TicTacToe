import { Component, DestroyRef, OnInit } from '@angular/core';
import { NgFor, NgIf, AsyncPipe, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Observable } from 'rxjs';
import { AuthService, AuthUser, UserSummary } from '../services/auth.service';
import { Invite, InviteService } from '../services/invite.service';
import { GameService, ShareableGame } from '../services/game.service';
import { WsService } from '../services/ws.service';

@Component({
  selector: 'app-lobby',
  standalone: true,
  imports: [NgFor, NgIf, AsyncPipe, FormsModule, DatePipe],
  templateUrl: './lobby.html',
})
export class LobbyComponent implements OnInit {
  user$!: Observable<AuthUser | null>;
  invites: Invite[] = [];
  games: ShareableGame[] = [];
  searchQuery = '';
  searchResults: UserSummary[] = [];
  busy = false;
  searchBusy = false;

  constructor(
    private auth: AuthService,
    private inviteService: InviteService,
    private ws: WsService,
    private gameService: GameService,
    private router: Router,
    private destroyRef: DestroyRef
  ) {
    this.user$ = this.auth.user$;
  }

  ngOnInit(): void {
    this.user$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((user) => {
        if (!user || !this.auth.token) return;
        this.connectSocket(this.auth.token);
        void this.loadInvites();
        void this.loadGames();
      });
  }

  async loadInvites(): Promise<void> {
    this.invites = await this.inviteService.listInvites();
  }

  async loadGames(): Promise<void> {
    this.games = await this.gameService.listGames();
  }

  async searchUsers(): Promise<void> {
    this.searchBusy = true;
    try {
      this.searchResults = await this.auth.searchUsers(this.searchQuery);
    } finally {
      this.searchBusy = false;
    }
  }

  async invite(user: UserSummary): Promise<void> {
    this.busy = true;
    try {
      await this.inviteService.createInvite(user.id);
      await this.loadInvites();
    } finally {
      this.busy = false;
    }
  }

  async cancel(invite: Invite): Promise<void> {
    this.busy = true;
    try {
      await this.inviteService.cancelInvite(invite.id);
      await this.loadInvites();
    } finally {
      this.busy = false;
    }
  }

  async accept(invite: Invite): Promise<void> {
    this.busy = true;
    try {
      await this.inviteService.acceptInvite(invite.id);
      await this.loadInvites();
      await this.loadGames();
    } finally {
      this.busy = false;
    }
  }

  async openGame(gameId: number): Promise<void> {
    await this.router.navigateByUrl(`/game/${gameId}`);
  }

  async deleteGame(gameId: number): Promise<void> {
    this.busy = true;
    try {
      await this.gameService.deleteGame(gameId);
      await this.loadGames();
    } finally {
      this.busy = false;
    }
  }

  async logout(): Promise<void> {
    await this.auth.logout();
    await this.router.navigateByUrl('/login');
  }

  async goToLocal(): Promise<void> {
    await this.router.navigateByUrl('/local');
  }

  isIncoming(invite: Invite, userId: number): boolean {
    return invite.to_user_id === userId;
  }

  private connectSocket(token: string): void {
    this.ws
      .connect(token)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((msg) => {
        if (msg?.type === 'invites:update') {
          void this.loadInvites();
        }
        if (msg?.type === 'game:update') {
          void this.loadGames();
        }
      });
  }
}

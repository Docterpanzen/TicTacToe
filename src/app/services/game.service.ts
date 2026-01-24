import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { AuthService } from './auth.service';

export type PlayerSymbol = 'X' | 'O';
export type Cell = PlayerSymbol | null;
export type BoardWinner = PlayerSymbol | 'Draw' | null;

export interface GameState {
  boards: Cell[][];
  boardWinners: BoardWinner[];
  currentPlayerId: number;
  globalWinner: BoardWinner;
  nextAllowedBoard: number | null;
}

export interface GameUser {
  id: number;
  username: string;
}

export interface GameResponse {
  id: number;
  host: GameUser;
  guest: GameUser;
  state: GameState;
}

export interface ShareableGame {
  id: number;
  status: 'active' | 'finished';
  updatedAt: string;
  host: GameUser;
  guest: GameUser;
}

@Injectable({ providedIn: 'root' })
export class GameService {
  constructor(private http: HttpClient, private auth: AuthService) {}

  async getGame(gameId: number): Promise<GameResponse> {
    return await firstValueFrom(
      this.http.get<GameResponse>(`/api/games/${gameId}`, {
        headers: this.authHeaders(),
      })
    );
  }

  async listGames(): Promise<ShareableGame[]> {
    const result = await firstValueFrom(
      this.http.get<{ games: ShareableGame[] }>('/api/games', {
        headers: this.authHeaders(),
      })
    );
    return result.games || [];
  }

  async deleteGame(gameId: number): Promise<void> {
    await firstValueFrom(
      this.http.delete(`/api/games/${gameId}`, {
        headers: this.authHeaders(),
      })
    );
  }

  async makeMove(gameId: number, boardIndex: number, cellIndex: number): Promise<GameResponse> {
    return await firstValueFrom(
      this.http.post<GameResponse>(
        `/api/games/${gameId}/move`,
        { boardIndex, cellIndex },
        { headers: this.authHeaders() }
      )
    );
  }

  private authHeaders(): HttpHeaders {
    const token = this.auth.token;
    return new HttpHeaders(token ? { Authorization: `Bearer ${token}` } : {});
  }
}

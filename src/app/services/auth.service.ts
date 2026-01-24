import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, firstValueFrom } from 'rxjs';

export interface AuthUser {
  id: number;
  username: string;
}

export interface UserSummary {
  id: number;
  username: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private tokenKey = 'ttt_token';
  private userSubject = new BehaviorSubject<AuthUser | null>(null);
  user$ = this.userSubject.asObservable();

  constructor(private http: HttpClient) {}

  get token(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  async init(): Promise<void> {
    if (!this.token) return;
    try {
      const user = await firstValueFrom(
        this.http.get<AuthUser>('/api/me', {
          headers: this.authHeaders(),
        })
      );
      this.userSubject.next(user);
    } catch {
      this.clearSession();
    }
  }

  async register(username: string, password: string): Promise<void> {
    await firstValueFrom(
      this.http.post('/api/register', { username, password })
    );
  }

  async login(username: string, password: string): Promise<void> {
    const result = await firstValueFrom(
      this.http.post<{ token: string }>('/api/login', { username, password })
    );
    localStorage.setItem(this.tokenKey, result.token);
    await this.init();
  }

  async logout(): Promise<void> {
    try {
      await firstValueFrom(
        this.http.post('/api/logout', {}, { headers: this.authHeaders() })
      );
    } finally {
      this.clearSession();
    }
  }

  async searchUsers(query: string): Promise<UserSummary[]> {
    const trimmed = query.trim();
    if (!trimmed) return [];
    const result = await firstValueFrom(
      this.http.get<{ users: UserSummary[] }>('/api/users/search', {
        headers: this.authHeaders(),
        params: { q: trimmed },
      })
    );
    return result.users || [];
  }

  private authHeaders(): HttpHeaders {
    const token = this.token;
    return new HttpHeaders(token ? { Authorization: `Bearer ${token}` } : {});
  }

  private clearSession(): void {
    localStorage.removeItem(this.tokenKey);
    this.userSubject.next(null);
  }
}

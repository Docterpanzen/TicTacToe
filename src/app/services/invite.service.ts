import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { AuthService } from './auth.service';
import { buildApiUrl } from './api-base';

export interface Invite {
  id: number;
  from_user_id: number;
  to_user_id: number;
  status: 'pending' | 'accepted' | 'canceled';
  created_at: string;
  from_username: string;
  to_username: string;
  from_public_id?: string;
  to_public_id?: string;
}

@Injectable({ providedIn: 'root' })
export class InviteService {
  constructor(private http: HttpClient, private auth: AuthService) {}

  async listInvites(): Promise<Invite[]> {
    const result = await firstValueFrom(
      this.http.get<{ invites: Invite[] }>(buildApiUrl('/api/invites'), {
        headers: this.authHeaders(),
      })
    );
    return result.invites || [];
  }

  async createInvite(toUserId: number): Promise<void> {
    await firstValueFrom(
      this.http.post(buildApiUrl('/api/invites'), { toUserId }, { headers: this.authHeaders() })
    );
  }

  async cancelInvite(inviteId: number): Promise<void> {
    await firstValueFrom(
      this.http.post(
        buildApiUrl(`/api/invites/${inviteId}/cancel`),
        {},
        { headers: this.authHeaders() }
      )
    );
  }

  async acceptInvite(inviteId: number): Promise<{ gameId: number }> {
    const result = await firstValueFrom(
      this.http.post<{ gameId: number }>(
        buildApiUrl(`/api/invites/${inviteId}/accept`),
        {},
        { headers: this.authHeaders() }
      )
    );
    return result;
  }

  private authHeaders(): HttpHeaders {
    const token = this.auth.token;
    return new HttpHeaders(token ? { Authorization: `Bearer ${token}` } : {});
  }
}

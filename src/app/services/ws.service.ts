import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';
import { resolveWsBaseUrl } from './api-base';

@Injectable({ providedIn: 'root' })
export class WsService {
  private socket?: WebSocket;
  private messages = new Subject<any>();

  connect(token: string): Observable<any> {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      return this.messages.asObservable();
    }

    const baseUrl = resolveWsBaseUrl();
    const url = `${baseUrl}/ws?token=${encodeURIComponent(token)}`;
    this.socket = new WebSocket(url);

    this.socket.onmessage = (event) => {
      try {
        this.messages.next(JSON.parse(event.data));
      } catch {
        this.messages.next({ type: 'unknown' });
      }
    };

    this.socket.onclose = () => {
      this.socket = undefined;
    };

    return this.messages.asObservable();
  }

  disconnect(): void {
    this.socket?.close();
    this.socket = undefined;
  }
}

import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class WsService {
  private socket?: WebSocket;
  private messages = new Subject<any>();

  connect(token: string): Observable<any> {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      return this.messages.asObservable();
    }

    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${protocol}://${location.host}/ws?token=${encodeURIComponent(token)}`;
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

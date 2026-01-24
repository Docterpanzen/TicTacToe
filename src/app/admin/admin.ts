import { Component, DestroyRef, OnInit } from '@angular/core';
import { NgFor, NgIf, AsyncPipe, DatePipe } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Observable } from 'rxjs';
import { AuthService, AdminUser, AuthUser } from '../services/auth.service';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [NgFor, NgIf, AsyncPipe, DatePipe, RouterLink],
  templateUrl: './admin.html',
})
export class AdminComponent implements OnInit {
  user$!: Observable<AuthUser | null>;
  users: AdminUser[] = [];
  busy = false;
  error = '';

  constructor(
    private auth: AuthService,
    private router: Router,
    private destroyRef: DestroyRef
  ) {
    this.user$ = this.auth.user$;
  }

  ngOnInit(): void {
    this.user$
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((user) => {
        if (!user) {
          void this.router.navigateByUrl('/login');
          return;
        }
        if (!user.isAdmin) {
          void this.router.navigateByUrl('/lobby');
          return;
        }
        void this.loadUsers();
      });
  }

  async loadUsers(): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      this.users = await this.auth.listUsers();
    } catch {
      this.error = 'Benutzer konnten nicht geladen werden.';
    } finally {
      this.busy = false;
    }
  }

  async deleteUser(user: AdminUser): Promise<void> {
    if (user.isAdmin) return;
    const confirmed = confirm(`Benutzer ${user.username} löschen?`);
    if (!confirmed) return;

    this.busy = true;
    this.error = '';
    try {
      await this.auth.deleteUser(user.id);
      await this.loadUsers();
    } catch {
      this.error = 'Benutzer konnte nicht gelöscht werden.';
    } finally {
      this.busy = false;
    }
  }
}

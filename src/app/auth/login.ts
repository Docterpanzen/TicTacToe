import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { NgIf } from '@angular/common';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, NgIf, RouterLink],
  templateUrl: './login.html',
})
export class LoginComponent {
  mode: 'login' | 'register' = 'login';
  username = '';
  password = '';
  error = '';
  busy = false;

  constructor(private auth: AuthService, private router: Router) {}

  toggleMode(): void {
    this.mode = this.mode === 'login' ? 'register' : 'login';
    this.error = '';
  }

  async submit(): Promise<void> {
    if (!this.username || !this.password) {
      this.error = 'Bitte Benutzername und Passwort eingeben.';
      return;
    }

    this.error = '';
    this.busy = true;

    try {
      if (this.mode === 'register') {
        await this.auth.register(this.username, this.password);
      }
      await this.auth.login(this.username, this.password);
      await this.router.navigateByUrl('/local');
    } catch (err) {
      this.error = 'Login fehlgeschlagen.';
    } finally {
      this.busy = false;
    }
  }
}

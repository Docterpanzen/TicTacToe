import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { NgClass, NgIf } from '@angular/common';
import { AuthService } from '../services/auth.service';
import { HttpErrorResponse } from '@angular/common/http';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, NgIf, NgClass, RouterLink],
  templateUrl: './login.html',
})
export class LoginComponent {
  mode: 'login' | 'register' = 'login';
  username = '';
  password = '';
  error = '';
  busy = false;

  adminUsername = '';
  adminPassword = '';
  adminError = '';
  showAdmin = false;

  private readonly passwordMinLength = 8;
  private readonly passwordHasLower = /[a-z]/;
  private readonly passwordHasUpper = /[A-Z]/;
  private readonly passwordHasSpecial = /[^A-Za-z0-9]/;
  private readonly usernamePattern = /^[a-z0-9_]+$/i;

  get isRegisterMode(): boolean {
    return this.mode === 'register';
  }

  get usernameTooShort(): boolean {
    return this.username.trim().length > 0 && this.username.trim().length < 3;
  }

  get usernameInvalid(): boolean {
    const trimmed = this.username.trim();
    return trimmed.length > 0 && !this.usernamePattern.test(trimmed);
  }

  get usernameReserved(): boolean {
    return this.username.trim().toLowerCase() === 'admin';
  }

  get passwordTooShort(): boolean {
    return this.password.length > 0 && this.password.length < this.passwordMinLength;
  }

  get passwordMissingSpecial(): boolean {
    return this.password.length > 0 && !this.passwordHasSpecial.test(this.password);
  }

  get passwordMissingUpperOrLower(): boolean {
    if (!this.password) return false;
    return !this.passwordHasUpper.test(this.password) || !this.passwordHasLower.test(this.password);
  }

  get passwordValid(): boolean {
    if (!this.password) return false;
    return (
      this.password.length >= this.passwordMinLength &&
      this.passwordHasSpecial.test(this.password) &&
      this.passwordHasUpper.test(this.password) &&
      this.passwordHasLower.test(this.password)
    );
  }

  constructor(private auth: AuthService, private router: Router) {}

  toggleMode(): void {
    this.mode = this.mode === 'login' ? 'register' : 'login';
    this.error = '';
  }

  toggleAdmin(): void {
    this.showAdmin = !this.showAdmin;
    this.adminError = '';
  }

  async submit(): Promise<void> {
    if (!this.username || !this.password) {
      this.error = 'Bitte Benutzername und Passwort eingeben.';
      return;
    }

    if (this.mode === 'register') {
      const validationError = this.validateRegistration();
      if (validationError) {
        this.error = validationError;
        return;
      }
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
      this.error = this.mapError(err);
    } finally {
      this.busy = false;
    }
  }

  async submitAdmin(): Promise<void> {
    if (!this.adminUsername || !this.adminPassword) {
      this.adminError = 'Bitte Admin-Benutzername und Passwort eingeben.';
      return;
    }

    this.adminError = '';
    this.busy = true;

    try {
      await this.auth.adminLogin(this.adminUsername, this.adminPassword);
      await this.router.navigateByUrl('/admin');
    } catch (err) {
      this.adminError = this.mapAdminError(err);
    } finally {
      this.busy = false;
    }
  }

  private validateRegistration(): string {
    if (this.username.trim().length < 3) {
      return 'Benutzername muss mindestens 3 Zeichen lang sein.';
    }

    if (!this.usernamePattern.test(this.username.trim())) {
      return 'Benutzername darf nur Buchstaben, Zahlen und Unterstrich enthalten.';
    }

    if (this.username.trim().toLowerCase() === 'admin') {
      return 'Benutzername ist nicht erlaubt.';
    }

    const password = this.password;
    if (password.length < this.passwordMinLength) {
      return `Passwort muss mindestens ${this.passwordMinLength} Zeichen lang sein.`;
    }
    if (!this.passwordHasSpecial.test(password)) {
      return 'Passwort muss mindestens ein Sonderzeichen enthalten.';
    }
    if (!this.passwordHasUpper.test(password) || !this.passwordHasLower.test(password)) {
      return 'Passwort muss mindestens einen Groß- und einen Kleinbuchstaben enthalten.';
    }

    return '';
  }

  private mapError(err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      const apiError = err.error?.error as string | undefined;
      const details = Array.isArray(err.error?.details) ? err.error.details : [];

      if (apiError === 'username_taken') {
        return 'Benutzername ist bereits vergeben.';
      }
      if (apiError === 'username_too_short') {
        return 'Benutzername muss mindestens 3 Zeichen lang sein.';
      }
      if (apiError === 'username_invalid') {
        return 'Benutzername darf nur Buchstaben, Zahlen und Unterstrich enthalten.';
      }
      if (apiError === 'username_reserved') {
        return 'Benutzername ist nicht erlaubt.';
      }
      if (apiError === 'password_invalid') {
        if (details.includes('password_too_short')) {
          return `Passwort muss mindestens ${this.passwordMinLength} Zeichen lang sein.`;
        }
        if (details.includes('password_missing_special')) {
          return 'Passwort muss mindestens ein Sonderzeichen enthalten.';
        }
        if (details.includes('password_missing_upper') || details.includes('password_missing_lower')) {
          return 'Passwort muss mindestens einen Groß- und einen Kleinbuchstaben enthalten.';
        }
        return 'Passwort erfüllt die Anforderungen nicht.';
      }
      if (apiError === 'missing_fields') {
        return 'Bitte Benutzername und Passwort eingeben.';
      }
      if (apiError === 'invalid_credentials') {
        return 'Benutzername oder Passwort ist falsch.';
      }
      if (apiError === 'admin_only') {
        return 'Admin bitte über den Admin-Login anmelden.';
      }
    }

    return this.mode === 'register' ? 'Registrierung fehlgeschlagen.' : 'Login fehlgeschlagen.';
  }

  private mapAdminError(err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      const apiError = err.error?.error as string | undefined;
      if (apiError === 'admin_only') {
        return 'Nur Admin-Zugang erlaubt.';
      }
      if (apiError === 'invalid_credentials') {
        return 'Admin-Benutzername oder Passwort ist falsch.';
      }
      if (apiError === 'missing_fields') {
        return 'Bitte Admin-Benutzername und Passwort eingeben.';
      }
    }
    return 'Admin-Anmeldung fehlgeschlagen.';
  }
}

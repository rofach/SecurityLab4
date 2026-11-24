import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import {
  AccountStatusResponse,
  ActiveTab,
  AuthOperationResponse
} from './models/auth.models';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit, OnDestroy {
  private readonly fb = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private timerHandle: ReturnType<typeof setInterval> | null = null;

  readonly activeTab = signal<ActiveTab>('login');
  readonly accountStatus = signal<AccountStatusResponse | null>(null);
  readonly lastResponse = signal<AuthOperationResponse | null>(null);
  readonly networkError = signal<string | null>(null);
  readonly isLoading = signal(false);
  readonly showPassword = signal(false);
  readonly waitSeconds = signal(0);
  readonly temporaryPassword = signal<string | null>(null);
  readonly copiedTemp = signal(false);
  readonly showChangePassword = signal(false);
  readonly loggedInUsername = signal<string | null>(null);
  readonly loggedInTempPassword = signal<string>('');

  readonly form = this.fb.nonNullable.group({
    username: ['student', [Validators.required]],
    password: ['']
  });

  readonly changeForm = this.fb.nonNullable.group({
    newPassword: ['']
  });

  readonly isLocked = computed(() => this.accountStatus()?.isLocked ?? false);

  readonly canReset = computed(() => {
    const s = this.accountStatus();
    return Boolean(s && (s.failedAttempts > 0 || s.isLocked));
  });

  ngOnInit(): void {
    this.loadStatus('student');
  }

  ngOnDestroy(): void {
    this.clearTimer();
  }

  setTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
    this.lastResponse.set(null);
    this.networkError.set(null);
    this.showChangePassword.set(false);
    this.form.controls.password.setValue('');
    if (tab === 'login') {
      const username = this.form.controls.username.value.trim();
      if (username) {
        this.loadStatus(username);
      }
    }
  }

  togglePasswordVisibility(): void {
    this.showPassword.update((v) => !v);
  }

  hasUpper(val: string): boolean {
    return /[A-ZА-ЯІЇЄҐ]/.test(val);
  }

  hasLower(val: string): boolean {
    return /[a-zа-яіїєґ]/.test(val);
  }

  hasDigit(val: string): boolean {
    return /\d/.test(val);
  }

  hasSpecial(val: string): boolean {
    return /[^A-Za-zА-Яа-яІіЇїЄєҐґ0-9]/.test(val);
  }

  onUsernameBlur(): void {
    if (this.activeTab() !== 'login') {
      return;
    }
    const username = this.form.controls.username.value.trim();
    if (username) {
      this.loadStatus(username);
    } else {
      this.accountStatus.set(null);
    }
  }

  onSubmit(): void {
    const username = this.form.controls.username.value.trim();
    const password = this.form.controls.password.value;
    if (!username) {
      this.form.controls.username.markAsTouched();
      return;
    }

    if (this.activeTab() === 'login' && (this.isLocked() || this.waitSeconds() > 0)) {
      return;
    }

    this.isLoading.set(true);
    this.networkError.set(null);

    const request$ =
      this.activeTab() === 'login'
        ? this.authService.login({ username, password })
        : this.authService.register({ username, password });

    request$.subscribe({
      next: (res) => {
        this.isLoading.set(false);
        this.lastResponse.set(res);
        if (res.accountStatus) {
          this.accountStatus.set(res.accountStatus);
        }
        this.startCountdown(res.retryAfterSeconds || res.accountStatus?.retryAfterSeconds || 0);

        if (res.succeeded && this.activeTab() === 'login') {
          this.temporaryPassword.set(null);
          if (res.accountStatus?.mustChangePassword) {
            this.loggedInUsername.set(username);
            this.loggedInTempPassword.set(password);
            this.changeForm.controls.newPassword.setValue('');
            this.showChangePassword.set(true);
          }
          this.form.controls.password.setValue('');
        } else if (res.succeeded && this.activeTab() === 'register') {
          this.form.controls.password.setValue('');
        }
      },
      error: () => {
        this.isLoading.set(false);
        this.networkError.set('Не вдалося звʼязатися із сервером.');
      }
    });
  }

  onChangePasswordSubmit(): void {
    const username = this.loggedInUsername();
    const currentPassword = this.loggedInTempPassword();
    const newPassword = this.changeForm.controls.newPassword.value;
    if (!username) {
      return;
    }

    this.isLoading.set(true);
    this.networkError.set(null);

    this.authService.changePassword({ username, currentPassword, newPassword }).subscribe({
      next: (res) => {
        this.isLoading.set(false);
        this.lastResponse.set(res);
        if (res.accountStatus) {
          this.accountStatus.set(res.accountStatus);
        }
        if (res.succeeded) {
          this.showChangePassword.set(false);
          this.loggedInUsername.set(null);
          this.loggedInTempPassword.set('');
          this.changeForm.controls.newPassword.setValue('');
        }
      },
      error: () => {
        this.isLoading.set(false);
        this.networkError.set('Не вдалося змінити пароль.');
      }
    });
  }

  skipPasswordChange(): void {
    this.showChangePassword.set(false);
    this.loggedInUsername.set(null);
    this.loggedInTempPassword.set('');
  }

  onReset(): void {
    const username = this.accountStatus()?.username ?? this.form.controls.username.value.trim();
    if (!username) {
      return;
    }

    this.isLoading.set(true);
    this.networkError.set(null);
    this.copiedTemp.set(false);

    this.authService.reset(username).subscribe({
      next: (res) => {
        this.isLoading.set(false);
        this.lastResponse.set(res);
        this.temporaryPassword.set(res.temporaryPassword);
        this.clearTimer();
        this.waitSeconds.set(0);
        if (res.accountStatus) {
          this.accountStatus.set(res.accountStatus);
        }
      },
      error: () => {
        this.isLoading.set(false);
        this.networkError.set('Не вдалося скинути стан.');
      }
    });
  }

  copyTempPassword(): void {
    const pwd = this.temporaryPassword();
    if (!pwd) {
      return;
    }
    navigator.clipboard.writeText(pwd).then(() => {
      this.copiedTemp.set(true);
      setTimeout(() => this.copiedTemp.set(false), 1500);
    });
  }

  private loadStatus(username: string): void {
    this.authService.getStatus(username).subscribe({
      next: (status) => {
        this.accountStatus.set(status);
        this.startCountdown(status.retryAfterSeconds);
      },
      error: () => this.accountStatus.set(null)
    });
  }

  private startCountdown(seconds: number): void {
    this.clearTimer();
    if (seconds <= 0) {
      this.waitSeconds.set(0);
      return;
    }
    this.waitSeconds.set(seconds);
    this.timerHandle = setInterval(() => {
      const next = this.waitSeconds() - 1;
      if (next <= 0) {
        this.waitSeconds.set(0);
        this.clearTimer();
      } else {
        this.waitSeconds.set(next);
      }
    }, 1000);
  }

  private clearTimer(): void {
    if (this.timerHandle !== null) {
      clearInterval(this.timerHandle);
      this.timerHandle = null;
    }
  }
}

export type ActiveTab = 'login' | 'register';

export interface AccountStatusResponse {
  username: string;
  minLength: number;
  maxAttempts: number;
  failedAttempts: number;
  remainingAttempts: number;
  isLocked: boolean;
  retryAfterSeconds: number;
  mustChangePassword: boolean;
}

export interface AuthOperationResponse {
  succeeded: boolean;
  statusCode: number;
  message: string;
  temporaryPassword: string | null;
  retryAfterSeconds: number;
  accountStatus: AccountStatusResponse | null;
}

export interface CredentialsRequest {
  username: string;
  password: string;
}

export interface ChangePasswordRequest {
  username: string;
  currentPassword: string;
  newPassword: string;
}

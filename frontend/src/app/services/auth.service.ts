import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, of, throwError } from 'rxjs';
import {
  AccountStatusResponse,
  AuthOperationResponse,
  ChangePasswordRequest,
  CredentialsRequest
} from '../models/auth.models';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/auth';

  register(payload: CredentialsRequest): Observable<AuthOperationResponse> {
    return this.http
      .post<AuthOperationResponse>(`${this.baseUrl}/register`, payload)
      .pipe(catchError((err: HttpErrorResponse) => this.extractApiResponse(err)));
  }

  login(payload: CredentialsRequest): Observable<AuthOperationResponse> {
    return this.http
      .post<AuthOperationResponse>(`${this.baseUrl}/login`, payload)
      .pipe(catchError((err: HttpErrorResponse) => this.extractApiResponse(err)));
  }

  changePassword(payload: ChangePasswordRequest): Observable<AuthOperationResponse> {
    return this.http
      .post<AuthOperationResponse>(`${this.baseUrl}/change-password`, payload)
      .pipe(catchError((err: HttpErrorResponse) => this.extractApiResponse(err)));
  }

  reset(username: string): Observable<AuthOperationResponse> {
    return this.http
      .post<AuthOperationResponse>(`${this.baseUrl}/reset`, { username })
      .pipe(catchError((err: HttpErrorResponse) => this.extractApiResponse(err)));
  }

  getStatus(username: string): Observable<AccountStatusResponse> {
    return this.http.get<AccountStatusResponse>(
      `${this.baseUrl}/status/${encodeURIComponent(username)}`
    );
  }

  private extractApiResponse(error: HttpErrorResponse): Observable<AuthOperationResponse> {
    if (error.error && typeof error.error === 'object' && 'message' in error.error) {
      return of(error.error as AuthOperationResponse);
    }
    return throwError(() => error);
  }
}

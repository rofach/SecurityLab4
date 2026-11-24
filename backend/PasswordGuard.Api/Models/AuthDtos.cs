namespace PasswordGuard.Api.Models;

public sealed record RegisterRequest(string Username, string Password);

public sealed record LoginRequest(string Username, string Password);

public sealed record ChangePasswordRequest(string Username, string CurrentPassword, string NewPassword);

public sealed record ResetRequest(string Username);

public sealed record AccountStatusResponse(
    string Username,
    int MinLength,
    int MaxAttempts,
    int FailedAttempts,
    int RemainingAttempts,
    bool IsLocked,
    int RetryAfterSeconds,
    bool MustChangePassword);

public sealed record AuthOperationResponse(
    bool Succeeded,
    int StatusCode,
    string Message,
    string? TemporaryPassword,
    int RetryAfterSeconds,
    AccountStatusResponse? AccountStatus);

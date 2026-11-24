namespace PasswordGuard.Api.Models;

public sealed class UserAccount
{
    public string Username { get; init; } = string.Empty;
    public byte[] Salt { get; set; } = [];
    public byte[] PasswordHash { get; set; } = [];
    public int FailedAttempts { get; set; }
    public bool IsLocked { get; set; }
    public bool MustChangePassword { get; set; }
    public DateTimeOffset? NextAllowedAttemptUtc { get; set; }
}

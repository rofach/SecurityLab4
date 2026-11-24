using System.Collections.Concurrent;
using PasswordGuard.Api.Models;

namespace PasswordGuard.Api.Services;

public sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, UserAccount> _users = new(StringComparer.OrdinalIgnoreCase);

    public InMemoryUserStore()
    {
        SeedUser("student", "SecurityLab4!2026");
    }

    public UserAccount? GetByUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        _users.TryGetValue(username.Trim(), out UserAccount? account);
        return account;
    }

    public bool TryAdd(UserAccount account)
    {
        return _users.TryAdd(account.Username, account);
    }

    private void SeedUser(string username, string password)
    {
        (byte[] salt, byte[] hash) = PasswordHasher.HashPassword(password);
        UserAccount account = new()
        {
            Username = username,
            Salt = salt,
            PasswordHash = hash
        };
        _users.TryAdd(username, account);
    }
}

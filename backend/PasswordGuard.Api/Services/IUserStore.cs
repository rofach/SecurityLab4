using PasswordGuard.Api.Models;

namespace PasswordGuard.Api.Services;

public interface IUserStore
{
    UserAccount? GetByUsername(string username);
    bool TryAdd(UserAccount account);
}

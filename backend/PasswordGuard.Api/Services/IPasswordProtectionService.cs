using PasswordGuard.Api.Models;

namespace PasswordGuard.Api.Services;

public interface IPasswordProtectionService
{
    AuthOperationResponse Register(RegisterRequest request);
    AuthOperationResponse Login(LoginRequest request);
    AuthOperationResponse ChangePassword(ChangePasswordRequest request);
    AuthOperationResponse Reset(ResetRequest request);
    AccountStatusResponse? GetStatus(string username);
}

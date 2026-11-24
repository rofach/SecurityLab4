using PasswordGuard.Api.Models;

namespace PasswordGuard.Api.Services;

public sealed class PasswordProtectionService(IUserStore userStore) : IPasswordProtectionService
{
    public const int MinLength = 15;
    public const int MaxAttempts = 10;

    public AuthOperationResponse Register(RegisterRequest request)
    {
        string username = (request.Username ?? string.Empty).Trim();
        string password = request.Password ?? string.Empty;

        if (string.IsNullOrWhiteSpace(username) || username.Length < 3)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status400BadRequest,
                "Логін повинен містити щонайменше 3 символи.",
                null,
                0,
                null);
        }

        string? validationError = ValidatePasswordPolicy(username, password);
        if (validationError is not null)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status400BadRequest,
                validationError,
                null,
                0,
                null);
        }

        if (userStore.GetByUsername(username) is not null)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status409Conflict,
                $"Користувач «{username}» вже існує.",
                null,
                0,
                null);
        }

        (byte[] salt, byte[] hash) = PasswordHasher.HashPassword(password);
        UserAccount account = new()
        {
            Username = username,
            Salt = salt,
            PasswordHash = hash
        };

        userStore.TryAdd(account);

        return new AuthOperationResponse(
            true,
            StatusCodes.Status201Created,
            $"Користувача «{username}» успішно зареєстровано.",
            null,
            0,
            BuildStatus(account));
    }

    public AuthOperationResponse Login(LoginRequest request)
    {
        string username = (request.Username ?? string.Empty).Trim();
        string password = request.Password ?? string.Empty;

        UserAccount? account = userStore.GetByUsername(username);
        if (account is null)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status404NotFound,
                $"Користувача «{username}» не знайдено.",
                null,
                0,
                null);
        }

        lock (account)
        {
            if (account.IsLocked || account.FailedAttempts >= MaxAttempts)
            {
                account.IsLocked = true;
                return new AuthOperationResponse(
                    false,
                    StatusCodes.Status423Locked,
                    "Введення пароля заблоковано (вичерпано 10 спроб).",
                    null,
                    0,
                    BuildStatus(account));
            }

            int waitSeconds = GetRemainingWaitSeconds(account.NextAllowedAttemptUtc);
            if (waitSeconds > 0)
            {
                return new AuthOperationResponse(
                    false,
                    StatusCodes.Status429TooManyRequests,
                    $"Зачекайте {waitSeconds} с перед наступною спробою.",
                    null,
                    waitSeconds,
                    BuildStatus(account));
            }

            if (password.Length < MinLength)
            {
                int delay = RegisterFailure(account);
                int remaining = MaxAttempts - account.FailedAttempts;

                string msg = account.IsLocked
                    ? $"Пароль закороткий (мін. {MinLength} символів). Вичерпано {MaxAttempts} спроб — введення заблоковано."
                    : delay > 0
                        ? $"Пароль закороткий (мін. {MinLength} символів). Залишилось спроб: {remaining} з {MaxAttempts}. Пауза {delay} с."
                        : $"Пароль закороткий (мін. {MinLength} символів). Залишилось спроб: {remaining} з {MaxAttempts}.";

                return new AuthOperationResponse(
                    false,
                    account.IsLocked ? StatusCodes.Status423Locked : StatusCodes.Status400BadRequest,
                    msg,
                    null,
                    delay,
                    BuildStatus(account));
            }

            bool isValid = PasswordHasher.VerifyPassword(password, account.Salt, account.PasswordHash);
            if (isValid)
            {
                account.FailedAttempts = 0;
                account.NextAllowedAttemptUtc = null;

                string okMsg = account.MustChangePassword
                    ? "Вхід виконано з тимчасовим паролем. Рекомендується змінити пароль."
                    : "Вхід виконано успішно.";

                return new AuthOperationResponse(
                    true,
                    StatusCodes.Status200OK,
                    okMsg,
                    null,
                    0,
                    BuildStatus(account));
            }

            int failDelay = RegisterFailure(account);
            int left = MaxAttempts - account.FailedAttempts;

            string failMsg = account.IsLocked
                ? $"Невірний пароль. Вичерпано {MaxAttempts} спроб — введення заблоковано."
                : failDelay > 0
                    ? $"Невірний пароль. Залишилось спроб: {left} з {MaxAttempts}. Пауза {failDelay} с."
                    : $"Невірний пароль. Залишилось спроб: {left} з {MaxAttempts}.";

            return new AuthOperationResponse(
                false,
                account.IsLocked ? StatusCodes.Status423Locked : StatusCodes.Status401Unauthorized,
                failMsg,
                null,
                failDelay,
                BuildStatus(account));
        }
    }

    public AuthOperationResponse ChangePassword(ChangePasswordRequest request)
    {
        string username = (request.Username ?? string.Empty).Trim();
        string currentPassword = request.CurrentPassword ?? string.Empty;
        string newPassword = request.NewPassword ?? string.Empty;

        UserAccount? account = userStore.GetByUsername(username);
        if (account is null)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status404NotFound,
                $"Користувача «{username}» не знайдено.",
                null,
                0,
                null);
        }

        lock (account)
        {
            if (account.IsLocked)
            {
                return new AuthOperationResponse(
                    false,
                    StatusCodes.Status423Locked,
                    "Зміна пароля недоступна: обліковий запис заблоковано.",
                    null,
                    0,
                    BuildStatus(account));
            }

            bool currentValid = PasswordHasher.VerifyPassword(currentPassword, account.Salt, account.PasswordHash);
            if (!currentValid)
            {
                return new AuthOperationResponse(
                    false,
                    StatusCodes.Status401Unauthorized,
                    "Невірний поточний пароль.",
                    null,
                    0,
                    BuildStatus(account));
            }

            string? validationError = ValidatePasswordPolicy(username, newPassword);
            if (validationError is not null)
            {
                return new AuthOperationResponse(
                    false,
                    StatusCodes.Status400BadRequest,
                    validationError,
                    null,
                    0,
                    BuildStatus(account));
            }

            (byte[] salt, byte[] hash) = PasswordHasher.HashPassword(newPassword);
            account.Salt = salt;
            account.PasswordHash = hash;
            account.MustChangePassword = false;
            account.FailedAttempts = 0;
            account.NextAllowedAttemptUtc = null;

            return new AuthOperationResponse(
                true,
                StatusCodes.Status200OK,
                "Пароль успішно змінено.",
                null,
                0,
                BuildStatus(account));
        }
    }

    public AuthOperationResponse Reset(ResetRequest request)
    {
        string username = (request.Username ?? string.Empty).Trim();
        UserAccount? account = userStore.GetByUsername(username);
        if (account is null)
        {
            return new AuthOperationResponse(
                false,
                StatusCodes.Status404NotFound,
                $"Користувача «{username}» не знайдено.",
                null,
                0,
                null);
        }

        lock (account)
        {
            string tempPassword = PasswordGenerator.Generate();
            (byte[] salt, byte[] hash) = PasswordHasher.HashPassword(tempPassword);

            account.Salt = salt;
            account.PasswordHash = hash;
            account.FailedAttempts = 0;
            account.IsLocked = false;
            account.NextAllowedAttemptUtc = null;
            account.MustChangePassword = true;

            return new AuthOperationResponse(
                true,
                StatusCodes.Status200OK,
                "Спроби скинуто. Згенеровано тимчасовий пароль (після входу змініть його).",
                tempPassword,
                0,
                BuildStatus(account));
        }
    }

    public AccountStatusResponse? GetStatus(string username)
    {
        UserAccount? account = userStore.GetByUsername(username);
        if (account is null)
        {
            return null;
        }

        lock (account)
        {
            return BuildStatus(account);
        }
    }

    private static string? ValidatePasswordPolicy(string username, string password)
    {
        if (password.Length < MinLength)
        {
            return $"Мінімальна довжина пароля — {MinLength} символів (введено {password.Length}).";
        }

        if (!password.Any(char.IsUpper))
        {
            return "Пароль повинен містити щонайменше одну велику літеру.";
        }

        if (!password.Any(char.IsLower))
        {
            return "Пароль повинен містити щонайменше одну малу літеру.";
        }

        if (!password.Any(char.IsDigit))
        {
            return "Пароль повинен містити щонайменше одну цифру.";
        }

        if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
        {
            return "Пароль повинен містити щонайменше один спецсимвол.";
        }

        if (!string.IsNullOrWhiteSpace(username) &&
            password.Contains(username, StringComparison.OrdinalIgnoreCase))
        {
            return "Пароль не повинен містити логін користувача.";
        }

        return null;
    }

    private static int ComputeDelaySeconds(int failedAttempts)
    {
        return failedAttempts switch
        {
            >= 10 => 0,
            >= 8 => 10,
            >= 6 => 5,
            >= 4 => 2,
            _ => 0
        };
    }

    private static int RegisterFailure(UserAccount account)
    {
        account.FailedAttempts = Math.Min(MaxAttempts, account.FailedAttempts + 1);
        if (account.FailedAttempts >= MaxAttempts)
        {
            account.IsLocked = true;
            account.NextAllowedAttemptUtc = null;
            return 0;
        }

        int delay = ComputeDelaySeconds(account.FailedAttempts);
        if (delay > 0)
        {
            account.NextAllowedAttemptUtc = DateTimeOffset.UtcNow.AddSeconds(delay);
        }

        return delay;
    }

    private static int GetRemainingWaitSeconds(DateTimeOffset? nextAllowedUtc)
    {
        if (nextAllowedUtc is null)
        {
            return 0;
        }

        double seconds = (nextAllowedUtc.Value - DateTimeOffset.UtcNow).TotalSeconds;
        return seconds > 0 ? (int)Math.Ceiling(seconds) : 0;
    }

    private static AccountStatusResponse BuildStatus(UserAccount account)
    {
        return new AccountStatusResponse(
            account.Username,
            MinLength,
            MaxAttempts,
            account.FailedAttempts,
            Math.Max(0, MaxAttempts - account.FailedAttempts),
            account.IsLocked,
            GetRemainingWaitSeconds(account.NextAllowedAttemptUtc),
            account.MustChangePassword);
    }
}

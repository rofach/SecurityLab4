using System.Security.Cryptography;

namespace PasswordGuard.Api.Services;

public static class PasswordGenerator
{
    private const string AllChars =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=?";

    public static string Generate(int length = 16)
    {
        int targetLength = Math.Max(15, length);
        string password;

        do
        {
            password = RandomNumberGenerator.GetString(AllChars, targetLength);
        }
        while (!password.Any(char.IsUpper)
            || !password.Any(char.IsLower)
            || !password.Any(char.IsDigit)
            || !password.Any(ch => !char.IsLetterOrDigit(ch)));

        return password;
    }
}

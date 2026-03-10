using Auth.Server.Models;
using Auth.Server.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;

namespace Auth.Server.Pages;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDistributedCache _cache;

    public string? ReturnUrl { get; set; }
    public string? AppName { get; set; }
    public string? Error { get; set; }
    public string? Username { get; set; }
    public string ActiveTab { get; set; } = "password";

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IDistributedCache cache)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cache = cache;
    }

    public void OnGet(string? returnUrl, string? error, string? tab)
    {
        ReturnUrl = returnUrl ?? "/";
        Error = error;
        ActiveTab = tab ?? "password";
    }

    // ── Логин по паролю ──────────────────────────────────────────────
    public async Task<IActionResult> OnPostPasswordAsync(
        string username, string password, string returnUrl)
    {
        ReturnUrl = returnUrl;

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            Error = "Введите логин и пароль.";
            Username = username;
            return Page();
        }

        // Ищем пользователя по username или email
        var user = await _userManager.FindByNameAsync(username)
                ?? await _userManager.FindByEmailAsync(username);

        if (user is null)
        {
            Error = "Неверный логин или пароль.";
            Username = username;
            return Page();
        }

        // Проверяем блокировку
        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            var minutes = (int)(lockoutEnd!.Value - DateTimeOffset.UtcNow).TotalMinutes + 1;
            Error = $"Аккаунт временно заблокирован. Попробуйте через {minutes} мин.";
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(
            user, password,
            isPersistent: false,
            lockoutOnFailure: true);

        if (result.Succeeded)
            return Redirect(returnUrl ?? "/");

        if (result.IsLockedOut)
        {
            Error = "Аккаунт заблокирован из-за множества неудачных попыток. Попробуйте через 5 минут.";
            return Page();
        }

        Error = "Неверный логин или пароль.";
        Username = username;
        ActiveTab = "password";
        return Page();
    }

    // ── Логин по OTP коду ────────────────────────────────────────────
    public async Task<IActionResult> OnPostOtpAsync(
        string email, string code, string returnUrl)
    {
        ReturnUrl = returnUrl;
        ActiveTab = "otp";

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(code))
        {
            Error = "Введите email и код.";
            return Page();
        }

        var storedCode = await _cache.GetStringAsync($"otp:{email}");

        if (storedCode is null)
        {
            Error = "Код истёк. Запросите новый.";
            return Page();
        }

        if (storedCode != code)
        {
            Error = "Неверный код. Проверьте письмо.";
            return Page();
        }

        // Удаляем использованный код
        await _cache.RemoveAsync($"otp:{email}");

        // Находим или создаём пользователя
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                CreatedAt = DateTime.UtcNow
            };
            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                Error = "Не удалось создать аккаунт. Попробуйте снова.";
                return Page();
            }
        }

        // Логиним пользователя (создаём Identity куку)
        await _signInManager.SignInAsync(user, isPersistent: false);
        return Redirect(returnUrl ?? "/");
    }
}

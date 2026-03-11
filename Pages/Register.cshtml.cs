using Auth.Server.Models;
using Auth.Server.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;

namespace Auth.Server.Pages;

public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDistributedCache _cache;
    private readonly IEmailService _emailService;
    private readonly IWebHostEnvironment _env;

    public string? Error { get; set; }
    public string? ReturnUrl { get; set; }

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        IDistributedCache cache,
        IEmailService emailService,
        IWebHostEnvironment env)
    {
        _userManager = userManager;
        _cache = cache;
        _emailService = emailService;
        _env = env;
    }

    public void OnGet(string? returnUrl)
    {
        ReturnUrl = returnUrl ?? "/";
    }

    public async Task<IActionResult> OnPostAsync(
        string email, string username, string password, string? returnUrl)
    {
        ReturnUrl = returnUrl ?? "/";

        if (string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password))
        {
            Error = "Заполните все поля.";
            return Page();
        }

        // Проверяем уникальность email и логина
        if (await _userManager.FindByEmailAsync(email) is not null)
        {
            Error = "Этот email уже зарегистрирован.";
            return Page();
        }

        if (await _userManager.FindByNameAsync(username) is not null)
        {
            Error = "Этот логин уже занят.";
            return Page();
        }

        // Создаём пользователя (не подтверждён)
        var user = new ApplicationUser
        {
            UserName = username,
            Email = email,
            EmailConfirmed = false,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            Error = result.Errors.First().Description;
            return Page();
        }

        // Генерируем и кэшируем код подтверждения
        var code = Random.Shared.Next(100_000, 999_999).ToString();
        await _cache.SetStringAsync($"confirm:{email}", code, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30)
        });

        // Отправляем письмо только в проде
        if (!_env.IsDevelopment())
        {
            try
            {
                await _emailService.SendConfirmAsync(email, username, code);
            }
            catch
            {
                // Удаляем пользователя если письмо не ушло
                await _userManager.DeleteAsync(user);
                await _cache.RemoveAsync($"confirm:{email}");
                Error = "Не удалось отправить письмо. Попробуйте позже.";
                return Page();
            }
        }

        return RedirectToPage("/Register/Confirm", new
        {
            email,
            returnUrl,
            code = _env.IsDevelopment() ? code : null
        });
    }
}

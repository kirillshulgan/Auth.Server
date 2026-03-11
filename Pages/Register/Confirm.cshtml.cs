using Auth.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;

namespace Auth.Server.Pages.Register;

public class ConfirmModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDistributedCache _cache;

    public string? Email { get; set; }
    public string? Error { get; set; }
    public string? ReturnUrl { get; set; }
    public string? DevCode { get; set; }

    public ConfirmModel(
        UserManager<ApplicationUser> userManager,
        IDistributedCache cache)
    {
        _userManager = userManager;
        _cache = cache;
    }

    public void OnGet(string email, string? returnUrl, string? code)
    {
        Email = email;
        ReturnUrl = returnUrl ?? "/";
        DevCode = code; // только в Development
    }

    public async Task<IActionResult> OnPostAsync(
        string email, string code, string? returnUrl)
    {
        Email = email;
        ReturnUrl = returnUrl ?? "/";

        var storedCode = await _cache.GetStringAsync($"confirm:{email}");

        if (storedCode is null)
        {
            Error = "Код истёк. Зарегистрируйтесь снова.";
            return Page();
        }

        if (storedCode != code)
        {
            Error = "Неверный код. Проверьте письмо.";
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            Error = "Пользователь не найден.";
            return Page();
        }

        // Подтверждаем email
        user.EmailConfirmed = true;
        await _userManager.UpdateAsync(user);
        await _cache.RemoveAsync($"confirm:{email}");

        return RedirectToPage("/Login", new
        {
            returnUrl,
            message = "Email подтверждён! Войдите в аккаунт."
        });
    }
}

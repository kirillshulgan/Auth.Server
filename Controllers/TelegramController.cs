using System.Security.Claims;
using Auth.Server.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Server.Controllers;

[Route("connect/social/telegram")]
[ApiController]
[Tags("Auth")]
public class TelegramController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public TelegramController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    // ── GET /connect/social/telegram ─────────────────────────────────
    // Открывается внутри popup — сразу редиректит на Telegram
    [HttpGet("")]
    public IActionResult Start([FromQuery] string? returnUrl)
    {
        var request = HttpContext.Request;
        var origin = $"{request.Scheme}://{request.Host}";

        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(Callback), "Telegram",
                new { returnUrl = returnUrl ?? "/" })
        };

        // Добавляем origin вручную через Items —
        // OnRedirectToIdentityProvider подхватит его
        properties.Items["origin"] = origin;

        return Challenge(properties, "Telegram");
    }

    // ── GET /connect/social/telegram/callback ─────────────────────────
    // Telegram редиректит сюда после авторизации (внутри popup)
    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string? returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);

        if (!result.Succeeded)
        {
            // Сообщаем об ошибке в родительское окно и закрываем popup
            return Content(BuildPostMessagePage("error", "Не удалось войти через Telegram."),
                "text/html");
        }

        var principal = result.Principal!;

        var telegramSub = principal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? principal.FindFirstValue("sub");

        if (string.IsNullOrEmpty(telegramSub))
        {
            return Content(
                BuildPostMessagePage("error", "Не удалось получить данные из Telegram."),
                "text/html");
        }

        var name = principal.FindFirstValue(ClaimTypes.Name)
            ?? principal.FindFirstValue("name")
            ?? "Telegram User";

        var preferredUsername = principal.FindFirstValue("preferred_username");

        var user = _userManager.Users
            .FirstOrDefault(u => u.TelegramId == telegramSub);

        if (user is null)
        {
            var userName = !string.IsNullOrEmpty(preferredUsername)
                ? $"tg_{preferredUsername}"
                : $"tg_{telegramSub}";

            if (await _userManager.FindByNameAsync(userName) is not null)
                userName = $"tg_{telegramSub}";

            user = new ApplicationUser
            {
                UserName = userName,
                DisplayName = name,
                TelegramId = telegramSub,
                EmailConfirmed = false,
                CreatedAt = DateTime.UtcNow
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                var error = createResult.Errors.First().Description;
                return Content(BuildPostMessagePage("error", error), "text/html");
            }
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(name) && user.DisplayName != name)
            {
                user.DisplayName = name;
                await _userManager.UpdateAsync(user);
            }
        }

        await _signInManager.SignInAsync(user, isPersistent: false);

        // Успех — отправляем postMessage и закрываем popup
        return Content(BuildPostMessagePage("success", returnUrl ?? "/"), "text/html");
    }

    // ── HTML страница которая отправляет postMessage и закрывается ────
    private static string BuildPostMessagePage(string status, string payload) => $$"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body>
            <script>
                try {
                    window.opener.postMessage(
                        { type: 'telegram-auth', status: '{{status}}', payload: '{{payload}}' },
                        window.location.origin
                    );
                } catch(e) {
                    console.error('postMessage failed', e);
                }
                window.close();
            </script>
            <p style="font-family:sans-serif;text-align:center;margin-top:40px;color:#6b7280">
                Закрываем окно...
            </p>
        </body>
        </html>
        """;
}

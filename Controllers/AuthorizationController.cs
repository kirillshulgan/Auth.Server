using Auth.Server.Models;
using Auth.Server.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Server.Controllers;

[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IDistributedCache _cache;
    private readonly IEmailService _emailService;

    public AuthorizationController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IDistributedCache cache,
        IEmailService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cache = cache;
        _emailService = emailService;
    }

    // ╔══════════════════════════════════════════════════════════════╗
    // ║  GET+POST /connect/authorize                                 ║
    // ║                                                              ║
    // ║  Точка входа Authorization Code Flow.                        ║
    // ║  Сюда попадает пользователь со стороннего сайта.             ║
    // ║  Если не залогинен — редиректим на /Login.                   ║
    // ║  Если залогинен — выдаём authorization_code и редиректим     ║
    // ║  обратно на redirect_uri клиента.                            ║
    // ╚══════════════════════════════════════════════════════════════╝
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [AllowAnonymous]
    [Tags("OAuth2")]
    [EndpointSummary("Старт авторизации")]
    [EndpointDescription("Authorization Code Flow. Редиректит на страницу логина если пользователь не залогинен.")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenIddict request не найден.");

        // Проверяем — есть ли уже залогиненный пользователь (кука Identity)
        var result = await HttpContext.AuthenticateAsync(
            IdentityConstants.ApplicationScheme);

        if (!result.Succeeded)
        {
            // Пользователь не залогинен.
            // Редиректим на /Login, сохранив текущий URL как ReturnUrl.
            // После логина пользователь вернётся сюда и мы выдадим code.
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path +
                                  QueryString.Create(
                                      Request.HasFormContentType
                                          ? [.. Request.Form]
                                          : [.. Request.Query])
                });
        }

        // Пользователь залогинен — находим его в базе
        var user = await _userManager.GetUserAsync(result.Principal!)
            ?? throw new InvalidOperationException("Пользователь не найден.");

        // Строим ClaimsPrincipal и подписываем его через OpenIddict.
        // OpenIddict сам сформирует authorization_code и сделает редирект
        // на redirect_uri клиента с параметром ?code=...
        var principal = await BuildPrincipalAsync(user, request);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // ╔══════════════════════════════════════════════════════════════╗
    // ║  POST /connect/token                                         ║
    // ║                                                              ║
    // ║  Универсальный эндпоинт для получения токенов.               ║
    // ║  Обрабатывает все grant types:                               ║
    // ║   - authorization_code (обмен code на token)                 ║
    // ║   - password           (логин + пароль напрямую)             ║
    // ║   - otp                (код из email)                        ║
    // ║   - refresh_token      (обновление токена)                   ║
    // ║   - client_credentials (межсервисный)                        ║
    // ╚══════════════════════════════════════════════════════════════╝
    [HttpPost("~/connect/token")]
    [Consumes("application/x-www-form-urlencoded")]
    [AllowAnonymous]
    [Tags("OAuth2")]
    [EndpointSummary("Получить токен")]
    [EndpointDescription("Поддерживает: password, authorization_code, refresh_token, client_credentials, otp")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenIddict request не найден.");

        // ── Authorization Code ───────────────────────────────────────────
        // Клиент обменивает code (полученный после логина) на access_token.
        // OpenIddict уже проверил code — нам нужно найти пользователя
        // и выдать финальный токен.
        if (request.IsAuthorizationCodeGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            var user = await _userManager.FindByIdAsync(
                principal.GetClaim(Claims.Subject)!);

            if (user is null)
                return ForbidWithError(Errors.InvalidGrant, "Пользователь не найден.");

            // Обновляем claims (роли могли измениться с момента выдачи code)
            return SignIn(
                await BuildPrincipalAsync(user, request),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // ── Password Flow ────────────────────────────────────────────────
        // Клиент отправляет username + password напрямую.
        // Ищем пользователя по username ИЛИ по email.
        if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByNameAsync(request.Username!)
                    ?? await _userManager.FindByEmailAsync(request.Username!);

            if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password!))
            {
                // Увеличиваем счётчик неудачных попыток (для lockout)
                if (user is not null)
                    await _userManager.AccessFailedAsync(user);

                return ForbidWithError(Errors.InvalidGrant, "Неверный логин или пароль.");
            }

            // Проверяем — не заблокирован ли аккаунт
            if (await _userManager.IsLockedOutAsync(user))
                return ForbidWithError(Errors.InvalidGrant, "Аккаунт временно заблокирован.");

            // Сбрасываем счётчик неудачных попыток
            await _userManager.ResetAccessFailedCountAsync(user);

            return SignIn(
                await BuildPrincipalAsync(user, request),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // ── OTP Flow (кастомный) ─────────────────────────────────────────
        // Клиент отправляет email + code.
        // Ищем код в кэше (он был сохранён при вызове /auth/send-otp).
        if (request.GrantType == "urn:ietf:params:oauth:grant-type:otp")
        {
            var email = request["email"]?.ToString();
            var code = request["code"]?.ToString();

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(code))
                return ForbidWithError(Errors.InvalidRequest, "Укажите email и code.");

            var storedCode = await _cache.GetStringAsync($"otp:{email}");

            if (storedCode is null)
                return ForbidWithError(Errors.InvalidGrant, "Код истёк или не был запрошен.");

            if (storedCode != code)
                return ForbidWithError(Errors.InvalidGrant, "Неверный код.");

            // Код верный — удаляем его (одноразовый)
            await _cache.RemoveAsync($"otp:{email}");

            // Находим или создаём пользователя по email
            var user = await _userManager.FindByEmailAsync(email)
                    ?? await CreateUserByEmailAsync(email);

            return SignIn(
                await BuildPrincipalAsync(user, request),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // ── Refresh Token ────────────────────────────────────────────────
        // Клиент обновляет истёкший access_token с помощью refresh_token.
        // OpenIddict уже проверил refresh_token — нам нужно актуализировать claims.
        if (request.IsRefreshTokenGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            var user = await _userManager.FindByIdAsync(
                principal.GetClaim(Claims.Subject)!);

            // Если пользователь удалён — отзываем refresh token
            if (user is null)
                return ForbidWithError(Errors.InvalidGrant, "Пользователь не найден.");

            if (await _userManager.IsLockedOutAsync(user))
                return ForbidWithError(Errors.InvalidGrant, "Аккаунт заблокирован.");

            return SignIn(
                await BuildPrincipalAsync(user, request),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // ── Client Credentials ───────────────────────────────────────────
        // Межсервисный запрос — нет пользователя.
        // OpenIddict проверяет client_id + client_secret.
        // Нам нечего добавить — просто подтверждаем.
        if (request.IsClientCredentialsGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            // Устанавливаем destinations для всех claims
            foreach (var claim in principal.Claims)
                claim.SetDestinations(Destinations.AccessToken);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException($"Grant type не поддерживается: {request.GrantType}");
    }

    // ╔══════════════════════════════════════════════════════════════╗
    // ║  GET /connect/userinfo                                       ║
    // ║                                                              ║
    // ║  Возвращает данные пользователя по access_token.             ║
    // ║  Клиент передаёт токен в заголовке Authorization: Bearer ... ║
    // ╚══════════════════════════════════════════════════════════════╝
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    [Tags("OAuth2")]
    [EndpointSummary("Данные пользователя")]
    [EndpointDescription("Возвращает claims пользователя по access_token. Требует scope: openid.")]
    [ProducesResponseType(typeof(UserInfoResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> UserInfo()
    {
        // Аутентификация через OpenIddict — НЕ через IdentityConstants
        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Проверяем что аутентификация прошла успешно
        if (result.Principal is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var user = await _userManager.FindByIdAsync(
            result.Principal.GetClaim(OpenIddictConstants.Claims.Subject)!);

        if (user is null)
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var claims = new Dictionary<string, object>
        {
            [OpenIddictConstants.Claims.Subject] = user.Id,
            [OpenIddictConstants.Claims.Email] = user.Email ?? string.Empty,
            [OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed,
            [OpenIddictConstants.Claims.Name] = user.DisplayName ?? user.UserName ?? string.Empty,
            [OpenIddictConstants.Claims.PreferredUsername] = user.UserName ?? string.Empty,
        };

        return Ok(claims);
    }

    // ╔══════════════════════════════════════════════════════════════╗
    // ║  GET+POST /connect/logout                                    ║
    // ║                                                              ║
    // ║  Выход пользователя: удаляем Identity куку,                  ║
    // ║  OpenIddict сам сделает редирект на post_logout_redirect_uri.║
    // ╚══════════════════════════════════════════════════════════════╝
    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    [AllowAnonymous]
    [Tags("OAuth2")]
    [EndpointSummary("Выход")]
    public async Task<IActionResult> Logout()
    {
        // Удаляем куку Identity (сессию пользователя на нашем сервере)
        await _signInManager.SignOutAsync();

        // Передаём управление обратно OpenIddict —
        // он сделает редирект на post_logout_redirect_uri клиента
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    // ╔══════════════════════════════════════════════════════════════╗
    // ║  POST /auth/send-otp                                         ║
    // ║                                                              ║
    // ║  Генерирует OTP код и отправляет его на email.               ║
    // ║  Код живёт 10 минут в кэше.                                  ║
    // ╚══════════════════════════════════════════════════════════════╝
    [HttpPost("~/auth/send-otp")]
    [AllowAnonymous]
    [Tags("Auth")]
    [EndpointSummary("Отправить OTP код")]
    [EndpointDescription("Отправляет 6-значный код на email. Cooldown 60 секунд между запросами.")]
    [ProducesResponseType(typeof(SendOtpResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SendOtp([FromBody] SendOtpRequest body)
    {
        if (string.IsNullOrWhiteSpace(body.Email))
            return BadRequest(new { error = "Email обязателен." });

        var cooldownKey = $"otp-cooldown:{body.Email}";
        if (await _cache.GetStringAsync(cooldownKey) is not null)
            return BadRequest(new { error = "Подождите 60 секунд перед повторной отправкой." });

        var code = Random.Shared.Next(100_000, 999_999).ToString();

        await _cache.SetStringAsync($"otp:{body.Email}", code, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)
        });

        await _cache.SetStringAsync(cooldownKey, "1", new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(60)
        });

        var isDevelopment = HttpContext.RequestServices
            .GetRequiredService<IWebHostEnvironment>().IsDevelopment();

        // В проде отправляем реально, в Development возвращаем код в ответе
        if (!isDevelopment)
        {
            try
            {
                await _emailService.SendOtpAsync(body.Email, code);
            }
            catch (Exception)
            {
                // Если SMTP упал — удаляем код из кэша чтобы можно было повторить
                await _cache.RemoveAsync($"otp:{body.Email}");
                await _cache.RemoveAsync(cooldownKey);
                return StatusCode(503, new { error = "Не удалось отправить письмо. Попробуйте позже." });
            }
        }

        return Ok(new
        {
            message = "Код отправлен.",
            code = isDevelopment ? code : null
        });
    }

    // ══════════════════════════════════════════════════════
    // HELPERS
    // ══════════════════════════════════════════════════════

    // Строим ClaimsPrincipal для пользователя.
    // Claims — это данные, которые будут зашиты в токен.
    // Destinations определяют: в какой токен попадёт каждый claim.
    private async Task<ClaimsPrincipal> BuildPrincipalAsync(
        ApplicationUser user,
        OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Базовые claims — всегда попадают в access_token
        identity
            .SetClaim(Claims.Subject, user.Id)
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Name, user.DisplayName ?? user.UserName)
            .SetClaim(Claims.PreferredUsername, user.UserName)
            .SetClaim(Claims.EmailVerified, user.EmailConfirmed.ToString().ToLower());

        // Роли — добавляем если запрошен scope roles
        if (request.HasScope(Scopes.Roles))
        {
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
                identity.AddClaim(new Claim(Claims.Role, role));
        }

        var principal = new ClaimsPrincipal(identity);

        // Устанавливаем запрошенные scopes — OpenIddict будет их проверять
        principal.SetScopes(request.GetScopes());

        // Устанавливаем destinations для каждого claim
        // AccessToken — зашифрованный JWT, который клиент передаёт в API
        // IdentityToken — содержит данные о пользователе для клиента
        principal.SetDestinations(GetDestinations);

        return principal;
    }

    // Определяем в какие токены попадёт каждый claim
    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            // Subject и Name — в оба токена
            Claims.Subject or
            Claims.Name or
            Claims.PreferredUsername
                => [Destinations.AccessToken, Destinations.IdentityToken],

            // Email — в оба, но только если запрошен scope email
            Claims.Email or
            Claims.EmailVerified
                => claim.Subject!.HasScope(Scopes.Email)
                    ? [Destinations.AccessToken, Destinations.IdentityToken]
                    : [Destinations.AccessToken],

            // Роли — в оба, но только если запрошен scope roles
            Claims.Role
                => claim.Subject!.HasScope(Scopes.Roles)
                    ? [Destinations.AccessToken, Destinations.IdentityToken]
                    : [Destinations.AccessToken],

            // Всё остальное — только в access_token
            _ => [Destinations.AccessToken]
        };
    }

    // Создаём нового пользователя при первом входе через OTP
    private async Task<ApplicationUser> CreateUserByEmailAsync(string email)
    {
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true, // Email подтверждён — пользователь получил код
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Не удалось создать пользователя: {errors}");
        }

        return user;
    }

    // Хелпер для возврата OAuth ошибки
    private IActionResult ForbidWithError(string error, string description)
    {
        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
            }));
    }
}

// Request model для /auth/send-otp
public record SendOtpRequest(string Email);

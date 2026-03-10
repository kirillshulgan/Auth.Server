using Auth.Server.Models;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Auth.Server.Workers;

public class DatabaseSeeder : IHostedService
{
    private readonly IServiceProvider _provider;
    private readonly ILogger<DatabaseSeeder> _logger;

    public DatabaseSeeder(IServiceProvider provider, ILogger<DatabaseSeeder> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _provider.CreateAsyncScope();
        var manager = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();

        await SeedWebClientAsync(manager, cancellationToken);
        await SeedMobileClientAsync(manager, cancellationToken);
        await SeedServiceClientAsync(manager, cancellationToken);

        await SeedTestUserAsync(scope.ServiceProvider, cancellationToken);

        _logger.LogInformation("DatabaseSeeder: клиенты проверены и созданы.");
    }

    // ───── Веб-клиент: Authorization Code + PKCE ─────────────────────────
    // Используется когда сторонний сайт отправляет пользователя на нашу
    // страницу логина. После входа пользователь редиректится обратно с code,
    // который сайт обменивает на токен через бэкенд-запрос.
    private async Task SeedWebClientAsync(
        IOpenIddictApplicationManager manager,
        CancellationToken ct)
    {
        const string clientId = "web-client";

        if (await manager.FindByClientIdAsync(clientId, ct) is not null)
        {
            _logger.LogDebug("Клиент {ClientId} уже существует, пропускаем.", clientId);
            return;
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = "web-client-secret-CHANGE-IN-PROD",
            DisplayName = "Web Client",
            ClientType = ClientTypes.Confidential, // Секрет хранится на сервере клиента

            // Куда редиректить после логина.
            // В проде добавить реальный домен приложения.
            RedirectUris =
            {
                new Uri("https://app.shulgan-lab.ru/callback"),
                new Uri("https://localhost:3000/callback"),  // Для локальной разработки
            },

            // Куда редиректить после logout
            PostLogoutRedirectUris =
            {
                new Uri("https://app.shulgan-lab.ru/"),
                new Uri("https://localhost:3000/"),
            },

            Permissions =
            {
                // Разрешённые эндпоинты
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,   // logout (OpenIddict 6.x)
                Permissions.Endpoints.Revocation,

                // Разрешённые flows
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,

                // Разрешённые response types
                Permissions.ResponseTypes.Code,

                // Разрешённые scopes
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                "scp:offline_access", // refresh token
            },

            Requirements =
            {
                // Обязательный PKCE — защита от перехвата authorization code
                Requirements.Features.ProofKeyForCodeExchange,
            }
        }, ct);

        _logger.LogInformation("Клиент {ClientId} создан.", clientId);
    }

    // ───── Мобильный/десктоп клиент: Password + OTP ──────────────────────
    // Используется для доверенных приложений (наши собственные),
    // которые могут принимать логин/пароль напрямую.
    private async Task SeedMobileClientAsync(
        IOpenIddictApplicationManager manager,
        CancellationToken ct)
    {
        const string clientId = "mobile-client";

        if (await manager.FindByClientIdAsync(clientId, ct) is not null)
        {
            _logger.LogDebug("Клиент {ClientId} уже существует, пропускаем.", clientId);
            return;
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = "mobile-client-secret-CHANGE-IN-PROD",
            DisplayName = "Mobile / Desktop Client",
            ClientType = ClientTypes.Confidential,

            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation,

                // Password flow — логин + пароль напрямую
                Permissions.GrantTypes.Password,

                // Кастомный OTP flow — вход по коду из email
                "gt:urn:ietf:params:oauth:grant-type:otp",

                Permissions.GrantTypes.RefreshToken,

                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                "scp:offline_access",
            }
        }, ct);

        _logger.LogInformation("Клиент {ClientId} создан.", clientId);
    }

    // ───── Сервисный клиент: Client Credentials ───────────────────────────
    // Используется другими микросервисами для межсервисного взаимодействия.
    // Нет пользователя — только сервис аутентифицирует себя.
    private async Task SeedServiceClientAsync(
        IOpenIddictApplicationManager manager,
        CancellationToken ct)
    {
        const string clientId = "service-client";

        if (await manager.FindByClientIdAsync(clientId, ct) is not null)
        {
            _logger.LogDebug("Клиент {ClientId} уже существует, пропускаем.", clientId);
            return;
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = "service-client-secret-CHANGE-IN-PROD",
            DisplayName = "Internal Service Client",
            ClientType = ClientTypes.Confidential,

            Permissions =
            {
                Permissions.Endpoints.Token,

                // Client Credentials — нет пользователя, только клиент
                Permissions.GrantTypes.ClientCredentials,

                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
            }
        }, ct);

        _logger.LogInformation("Клиент {ClientId} создан.", clientId);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SeedTestUserAsync(
    IServiceProvider services,
    CancellationToken ct)
    {
        // Этот метод только для Development — в продакшене удалить!
        var env = services.GetRequiredService<IWebHostEnvironment>();
        if (!env.IsDevelopment()) return;

        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

        const string email = "test@test.com";
        const string password = "Test1234!";

        if (await userManager.FindByEmailAsync(email) is not null)
        {
            _logger.LogDebug("Тестовый пользователь уже существует, пропускаем.");
            return;
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            DisplayName = "Test User",
            CreatedAt = DateTime.UtcNow
        };

        var result = await userManager.CreateAsync(user, password);

        if (result.Succeeded)
            _logger.LogInformation("Тестовый пользователь создан: {Email} / {Password}", email, password);
        else
            _logger.LogError("Ошибка создания тестового пользователя: {Errors}",
                string.Join(", ", result.Errors.Select(e => e.Description)));
    }
}

using Auth.Server.Data;
using Auth.Server.Infrastructure;
using Auth.Server.Models;
using Auth.Server.Services;
using Auth.Server.Workers;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// ╔══════════════════════════════════════════╗
// ║           БАЗА ДАННЫХ                    ║
// ╚══════════════════════════════════════════╝
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default"));
    // UseOpenIddict() говорит EF Core добавить таблицы OpenIddict в этот контекст
    options.UseOpenIddict();
});

// ╔══════════════════════════════════════════╗
// ║           ASP.NET CORE IDENTITY          ║
// ╚══════════════════════════════════════════╝
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.User.RequireUniqueEmail = true;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddAuthentication()
    .AddOpenIdConnect("Telegram", "Telegram", options =>
    {
        options.Authority = "https://oauth.telegram.org";
        options.ClientId = builder.Configuration["Auth:Telegram:ClientId"]!;
        options.ClientSecret = builder.Configuration["Auth:Telegram:ClientSecret"]!;
        options.ResponseType = "code";
        options.UsePkce = true;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.CallbackPath = "/connect/social/telegram/callback";
        options.GetClaimsFromUserInfoEndpoint = false;
        options.SaveTokens = false;

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                var request = context.HttpContext.Request;

                // Берём origin из Properties если передан, иначе из запроса
                var origin = context.Properties.Items.TryGetValue("origin", out var o)
                    ? o
                    : $"{request.Scheme}://{request.Host}";

                context.ProtocolMessage.SetParameter("origin", origin);
                return Task.CompletedTask;
            },

            OnRemoteFailure = context =>
            {
                // Если ошибка внутри popup — закрываем его через postMessage
                var html = """
            <!DOCTYPE html><html><body>
            <script>
                window.opener?.postMessage(
                    { type: 'telegram-auth', status: 'error', payload: 'Вход отменён.' },
                    window.location.origin
                );
                window.close();
            </script>
            </body></html>
            """;
                context.Response.ContentType = "text/html";
                context.Response.WriteAsync(html);
                context.HandleResponse();
                return Task.CompletedTask;
            }
        };
    });

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.LogoutPath = "/connect/logout";
    options.AccessDeniedPath = "/Login";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
});


// ╔══════════════════════════════════════════╗
// ║           OPENIDDICT                     ║
// ╚══════════════════════════════════════════╝
builder.Services.AddOpenIddict()

    // ── Core: хранилище данных ──────────────────────────────────────
    .AddCore(options =>
    {
        // Используем EF Core + наш DbContext для хранения
        // приложений, токенов, авторизаций и scopes
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })

    // ── Server: настройка сервера авторизации ───────────────────────
    .AddServer(options =>
    {
        // Эндпоинты — исправлены под OpenIddict 6.x
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo")       // ← UserInfo (с большой I)
            .SetEndSessionEndpointUris("connect/logout")       // ← EndSession вместо Logout
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetRevocationEndpointUris("connect/revoke")
            .SetJsonWebKeySetEndpointUris("connect/jwks");     // ← JsonWebKeySet вместо Cryptography

        // Grant types
        options
            .AllowAuthorizationCodeFlow()
            .AllowPasswordFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow()
            .AllowCustomFlow("urn:ietf:params:oauth:grant-type:otp");

        // Scopes
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            "offline_access"
        );

        // Время жизни токенов
        options.SetAccessTokenLifetime(TimeSpan.FromHours(1));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
        options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));

        // Сертификаты
        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // ASP.NET Core интеграция — исправлены под OpenIddict 6.x
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()          // ← EndSession вместо Logout
               .EnableUserInfoEndpointPassthrough()            // ← UserInfo (с большой I)
               .DisableTransportSecurityRequirement();
    })

    // ── Validation: валидация токенов в этом же приложении ─────────
    .AddValidation(options =>
    {
        // Используем локальный сервер как источник истины
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// ╔══════════════════════════════════════════╗
// ║           КЭШ ДЛЯ OTP КОДОВ             ║
// ╚══════════════════════════════════════════╝
// В памяти для разработки. На шаге 12 заменим на Redis
builder.Services.AddDistributedMemoryCache();

// ╔══════════════════════════════════════════╗
// ║           СЕРВИСЫ                        ║
// ╚══════════════════════════════════════════╝
builder.Services.AddTransient<IEmailService, SmtpEmailService>();

// Seeder запустится при старте приложения и создаст OAuth клиентов
builder.Services.AddHostedService<DatabaseSeeder>();

// ╔══════════════════════════════════════════╗
// ║           MVC + RAZOR PAGES              ║
// ╚══════════════════════════════════════════╝
builder.Services.AddControllersWithViews();

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, ct) =>
    {
        document.Info = new()
        {
            Title = "Shulgan Auth Server",
            Version = "v1",
            Description = "Сервис аутентификации и авторизации. Реализует OAuth 2.0 / OpenID Connect.",
            Contact = new() { Name = "shulgan-lab.ru" }
        };
        return Task.CompletedTask;
    });

    // Описываем OAuth2 схему для Scalar UI
    options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
});

builder.Services.AddRazorPages();

// ╔══════════════════════════════════════════╗
// ║           SESSION (для OAuth state)      ║
// ╚══════════════════════════════════════════╝
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// ╔══════════════════════════════════════════╗
// ║           CORS (для API клиентов)        ║
// ╚══════════════════════════════════════════╝
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

// ════════════════════════════════════════════
var app = builder.Build();
// ════════════════════════════════════════════

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
                     | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "Shulgan Auth API";
        options.Theme = ScalarTheme.DeepSpace;
        options.DefaultHttpClient = new(ScalarTarget.CSharp, ScalarClient.HttpClient);

        // Новый API для OAuth2 в Scalar 2.x
        options
            .AddPreferredSecuritySchemes("Bearer")
            .AddPasswordFlow("OAuth2", flow =>
            {
                flow.ClientId = "mobile-client";
                flow.SelectedScopes = ["openid", "email", "profile", "roles"];
            });
    });
}

// ╔══════════════════════════════════════════╗
// ║           АВТО-МИГРАЦИЯ                  ║
// ╚══════════════════════════════════════════╝
// При каждом старте применяем все незакрытые миграции.
// Безопасно — EF Core не трогает уже применённые.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();
}

// ╔══════════════════════════════════════════╗
// ║           MIDDLEWARE PIPELINE            ║
// ╚══════════════════════════════════════════╝
// Порядок важен! Каждый middleware передаёт запрос следующему.

app.UseStaticFiles();       // Отдаём wwwroot/css, wwwroot/js
app.UseCors("AllowAll");    // CORS заголовки
app.UseRouting();           // Определяем маршрут запроса
app.UseSession();           // Загружаем сессию (до Authentication)
app.UseAuthentication();    // Читаем куки / токены, устанавливаем User
app.UseAuthorization();     // Проверяем права доступа

app.MapControllers();       // Контроллеры (AuthorizationController)
app.MapRazorPages();        // Razor Pages (Login)

// Редирект с корня на страницу логина
app.MapGet("/", () => Results.Redirect("/Login"));

app.Run();

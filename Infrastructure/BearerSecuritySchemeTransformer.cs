using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi; // ← всё из Microsoft.OpenApi, Models больше нет!

namespace Auth.Server.Infrastructure;

public class BearerSecuritySchemeTransformer : IOpenApiDocumentTransformer
{
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public BearerSecuritySchemeTransformer(IAuthenticationSchemeProvider schemeProvider)
        => _schemeProvider = schemeProvider;

    public async Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken ct)
    {
        await Task.CompletedTask;

        document.Components ??= new OpenApiComponents();

        // IDictionary<string, IOpenApiSecurityScheme> — интерфейс, не конкретный тип
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();

        // ── Bearer JWT ───────────────────────────────────────────────────
        document.AddComponent("Bearer", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Вставьте access_token полученный с /connect/token"
        });

        // ── OAuth2 (Password + Authorization Code) ───────────────────────
        document.AddComponent("OAuth2", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.OAuth2,
            Flows = new OpenApiOAuthFlows
            {
                Password = new OpenApiOAuthFlow
                {
                    TokenUrl = new Uri("/connect/token", UriKind.Relative),
                    Scopes = new Dictionary<string, string>
                    {
                        ["openid"] = "OpenID",
                        ["email"] = "Email пользователя",
                        ["profile"] = "Профиль пользователя",
                        ["roles"] = "Роли пользователя",
                        ["offline_access"] = "Refresh token"
                    }
                },
                AuthorizationCode = new OpenApiOAuthFlow
                {
                    AuthorizationUrl = new Uri("/connect/authorize", UriKind.Relative),
                    TokenUrl = new Uri("/connect/token", UriKind.Relative),
                    Scopes = new Dictionary<string, string>
                    {
                        ["openid"] = "OpenID",
                        ["email"] = "Email пользователя",
                        ["profile"] = "Профиль пользователя",
                        ["roles"] = "Роли пользователя",
                        ["offline_access"] = "Refresh token"
                    }
                }
            }
        });

        // ── Глобальный security requirement ─────────────────────────────
        // OpenApiSecuritySchemeReference требует document вторым аргументом
        document.Security =
        [
            new OpenApiSecurityRequirement
            {
                // List<string> вместо string[] — требование нового API
                { new OpenApiSecuritySchemeReference("Bearer", document), new List<string>() }
            }
        ];

        // Обязательно — связывает все ссылки с документом
        document.SetReferenceHostDocument();
    }
}

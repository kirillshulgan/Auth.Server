namespace Auth.Server.Models;

public record TokenResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string? RefreshToken,
    string? IdToken,
    string? Scope
);

public record UserInfoResponse(
    string Sub,
    string Email,
    bool EmailVerified,
    string Name,
    string PreferredUsername,
    string[]? Roles
);

public record SendOtpResponse(
    string Message,
    string? Code  // Только в Development
);

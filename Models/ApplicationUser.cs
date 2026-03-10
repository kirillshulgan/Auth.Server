using Microsoft.AspNetCore.Identity;

namespace Auth.Server.Models;

public class ApplicationUser : IdentityUser
{
    /// <summary>Отображаемое имя (ФИО или никнейм)</summary>
    public string? DisplayName { get; set; }

    /// <summary>Telegram ID для входа через Telegram</summary>
    public string? TelegramId { get; set; }

    /// <summary>Google Subject ID для входа через Google</summary>
    public string? GoogleId { get; set; }

    /// <summary>Дата регистрации</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

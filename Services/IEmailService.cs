namespace Auth.Server.Services;

public interface IEmailService
{
    /// <summary>Отправить OTP код на email</summary>
    Task SendOtpAsync(string email, string code);

    /// <summary>Отправить приветственное письмо новому пользователю</summary>
    Task SendWelcomeAsync(string email, string displayName);
}

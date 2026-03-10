using System.Net;
using System.Net.Mail;

namespace Auth.Server.Services;

public class SmtpEmailService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<SmtpEmailService> _logger;

    public SmtpEmailService(IConfiguration config, ILogger<SmtpEmailService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public async Task SendOtpAsync(string email, string code)
    {
        var subject = "Ваш код входа";
        var body = BuildOtpEmailBody(code);
        await SendAsync(email, subject, body);
    }

    public async Task SendWelcomeAsync(string email, string displayName)
    {
        var subject = "Добро пожаловать!";
        var body = BuildWelcomeEmailBody(displayName);
        await SendAsync(email, subject, body);
    }

    // ───── Ядро отправки ─────────────────────────────────────────────
    private async Task SendAsync(string to, string subject, string htmlBody)
    {
        try
        {
            var host = _config["Smtp:Host"]!;
            var port = int.Parse(_config["Smtp:Port"]!);
            var user = _config["Smtp:User"]!;
            var password = _config["Smtp:Password"]!;
            var from = _config["Smtp:From"]!;
            var fromName = _config["Smtp:FromName"] ?? "Shulgan Auth";
            var enableSsl = bool.Parse(_config["Smtp:EnableSsl"] ?? "true");

            using var client = new SmtpClient(host, port)
            {
                Credentials = new NetworkCredential(user, password),
                EnableSsl = enableSsl,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Timeout = 10_000 // 10 секунд
            };

            using var message = new MailMessage
            {
                From = new MailAddress(from, fromName),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true,
                BodyEncoding = System.Text.Encoding.UTF8,
                SubjectEncoding = System.Text.Encoding.UTF8
            };
            message.To.Add(to);

            await client.SendMailAsync(message);
            _logger.LogInformation("Email отправлен: {To} / {Subject}", to, subject);
        }
        catch (Exception ex)
        {
            // Логируем ошибку но НЕ бросаем исключение —
            // сбой email не должен ломать весь flow авторизации
            _logger.LogError(ex, "Ошибка отправки email на {To}", to);
            throw; // Пробрасываем чтобы контроллер мог вернуть понятную ошибку
        }
    }

    // ───── HTML шаблон OTP письма ─────────────────────────────────────
    private static string BuildOtpEmailBody(string code)
    {
        // Разбиваем код на цифры для красивого отображения
        var digits = string.Join("</td><td style='padding:0 4px'>", code.ToCharArray());

        return $"""
        <!DOCTYPE html>
        <html lang="ru">
        <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:40px 20px">
            <tr><td align="center">
              <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">

                <!-- Шапка -->
                <tr>
                  <td style="background:linear-gradient(135deg,#667eea,#764ba2);padding:32px;text-align:center">
                    <div style="width:56px;height:56px;background:rgba(255,255,255,0.2);border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center">
                      <span style="font-size:28px">🔐</span>
                    </div>
                    <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700">Код подтверждения</h1>
                    <p style="margin:8px 0 0;color:rgba(255,255,255,0.8);font-size:14px">auth.shulgan-lab.ru</p>
                  </td>
                </tr>

                <!-- Тело -->
                <tr>
                  <td style="padding:40px 32px;text-align:center">
                    <p style="margin:0 0 24px;color:#374151;font-size:16px">
                      Ваш одноразовый код для входа:
                    </p>

                    <!-- Код -->
                    <table cellpadding="0" cellspacing="0" style="margin:0 auto 24px">
                      <tr>
                        <td style="padding:0 4px">{digits}</td>
                      </tr>
                    </table>
                    <div style="display:inline-block;background:#f3f4f6;border-radius:12px;padding:16px 32px;margin-bottom:24px">
                      <span style="font-size:36px;font-weight:800;letter-spacing:12px;color:#6366f1">{code}</span>
                    </div>

                    <p style="margin:0 0 8px;color:#6b7280;font-size:14px">
                      ⏱ Код действителен <strong>10 минут</strong>
                    </p>
                    <p style="margin:0;color:#9ca3af;font-size:13px">
                      Если вы не запрашивали код — просто проигнорируйте это письмо.
                    </p>
                  </td>
                </tr>

                <!-- Подвал -->
                <tr>
                  <td style="background:#f9fafb;padding:20px 32px;text-align:center;border-top:1px solid #e5e7eb">
                    <p style="margin:0;color:#9ca3af;font-size:12px">
                      © 2026 Shulgan Lab · <a href="https://auth.shulgan-lab.ru" style="color:#6366f1;text-decoration:none">auth.shulgan-lab.ru</a>
                    </p>
                  </td>
                </tr>

              </table>
            </td></tr>
          </table>
        </body>
        </html>
        """;
    }

    // ───── HTML шаблон приветственного письма ─────────────────────────
    private static string BuildWelcomeEmailBody(string displayName)
    {
        return $"""
        <!DOCTYPE html>
        <html lang="ru">
        <head><meta charset="UTF-8"></head>
        <body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:40px 20px">
            <tr><td align="center">
              <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
                <tr>
                  <td style="background:linear-gradient(135deg,#667eea,#764ba2);padding:32px;text-align:center">
                    <h1 style="margin:0;color:#ffffff;font-size:22px">👋 Добро пожаловать!</h1>
                  </td>
                </tr>
                <tr>
                  <td style="padding:40px 32px;text-align:center">
                    <p style="margin:0 0 16px;color:#374151;font-size:16px">
                      Привет, <strong>{displayName}</strong>!
                    </p>
                    <p style="margin:0;color:#6b7280;font-size:14px">
                      Ваш аккаунт на <strong>auth.shulgan-lab.ru</strong> успешно создан.
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="background:#f9fafb;padding:20px 32px;text-align:center;border-top:1px solid #e5e7eb">
                    <p style="margin:0;color:#9ca3af;font-size:12px">© 2026 Shulgan Lab</p>
                  </td>
                </tr>
              </table>
            </td></tr>
          </table>
        </body>
        </html>
        """;
    }
}

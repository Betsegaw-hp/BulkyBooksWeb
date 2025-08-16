using Microsoft.AspNetCore.Identity.UI.Services;

namespace BulkyBooksWeb.Services
{
    public interface IMailgunEmailService : IEmailSender
    {
        new Task SendEmailAsync(string email, string subject, string htmlMessage);
        Task SendEmailConfirmationAsync(string email, string name, string confirmationLink);
        Task SendPasswordResetAsync(string email, string name, string resetLink);
    }
}

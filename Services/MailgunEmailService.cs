using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace BulkyBooksWeb.Services
{
    public class MailgunEmailService : IMailgunEmailService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<MailgunEmailService> _logger;

        public MailgunEmailService(HttpClient httpClient, IConfiguration configuration, ILogger<MailgunEmailService> logger)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var apiKey = _configuration["Mailgun:ApiKey"];
                var domain = _configuration["Mailgun:Domain"];
                var fromEmail = _configuration["Mailgun:FromEmail"];
                var fromName = _configuration["Mailgun:FromName"];

                if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(domain))
                {
                    _logger.LogError("Mailgun configuration is missing. Please check ApiKey and Domain in appsettings.");
                    return;
                }

                var form = new List<KeyValuePair<string, string>>
                {
                    new("from", $"{fromName} <{fromEmail}>"),
                    new("to", email),
                    new("subject", subject),
                    new("html", htmlMessage)
                };

                var formContent = new FormUrlEncodedContent(form);

                // Set up authentication
                var authToken = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{apiKey}"));
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", authToken);

                var response = await _httpClient.PostAsync($"https://api.mailgun.net/v3/{domain}/messages", formContent);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation($"Email sent successfully to {email}");
                }
                else
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Failed to send email to {email}. Status: {response.StatusCode}, Response: {responseContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Exception occurred while sending email to {email}");
            }
        }

        public async Task SendEmailConfirmationAsync(string email, string name, string confirmationLink)
        {
            var subject = "Confirm your email - BulkyBooks";
            var htmlMessage = $@"
                <html>
                <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                        <div style='text-align: center; margin-bottom: 30px;'>
                            <h1 style='color: #007bff;'>BulkyBooks</h1>
                        </div>
                        
                        <h2>Welcome to BulkyBooks, {name}!</h2>
                        
                        <p>Thank you for registering with BulkyBooks. To complete your registration and start exploring our vast collection of books, please confirm your email address.</p>
                        
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{confirmationLink}' 
                               style='background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;'>
                                Confirm Email Address
                            </a>
                        </div>
                        
                        <p>If you cannot click the button above, please copy and paste the following link into your browser:</p>
                        <p style='word-break: break-all; color: #007bff;'>{confirmationLink}</p>
                        
                        <p>If you did not create this account, please ignore this email.</p>
                        
                        <hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>
                        <p style='font-size: 12px; color: #666; text-align: center;'>
                            This email was sent by BulkyBooks. If you have any questions, please contact our support team.
                        </p>
                    </div>
                </body>
                </html>";

            await SendEmailAsync(email, subject, htmlMessage);
        }

        public async Task SendPasswordResetAsync(string email, string name, string resetLink)
        {
            var subject = "Reset your password - BulkyBooks";
            var htmlMessage = $@"
                <html>
                <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                        <div style='text-align: center; margin-bottom: 30px;'>
                            <h1 style='color: #007bff;'>BulkyBooks</h1>
                        </div>
                        
                        <h2>Password Reset Request</h2>
                        
                        <p>Hello {name},</p>
                        
                        <p>We received a request to reset your password for your BulkyBooks account. If you made this request, please click the button below to reset your password:</p>
                        
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{resetLink}' 
                               style='background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;'>
                                Reset Password
                            </a>
                        </div>
                        
                        <p>If you cannot click the button above, please copy and paste the following link into your browser:</p>
                        <p style='word-break: break-all; color: #dc3545;'>{resetLink}</p>
                        
                        <p><strong>Important:</strong> This link will expire in 24 hours for security reasons.</p>
                        
                        <p>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
                        
                        <hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>
                        <p style='font-size: 12px; color: #666; text-align: center;'>
                            This email was sent by BulkyBooks. If you have any questions, please contact our support team.
                        </p>
                    </div>
                </body>
                </html>";

            await SendEmailAsync(email, subject, htmlMessage);
        }
    }
}

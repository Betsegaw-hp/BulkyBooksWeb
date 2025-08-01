using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace BulkyBooksWeb.Models.ViewModels
{
    // Profile management view models
    public class ProfileManagementViewModel
    {
        public PersonalInfoViewModel PersonalInfo { get; set; } = new();
        public AccountSecurityViewModel Security { get; set; } = new();
        public NotificationSettingsViewModel Notifications { get; set; } = new();
        public ConnectedAccountsViewModel ConnectedAccounts { get; set; } = new();
        public string ActiveTab { get; set; } = "personal";
    }

    public class PersonalInfoViewModel
    {
        public string UserId { get; set; } = string.Empty;

        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        public string LastName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Invalid phone number")]
        public string PhoneNumber { get; set; } = string.Empty;

        public string UserName { get; set; } = string.Empty;
        public string CurrentAvatarUrl { get; set; } = string.Empty;
        public IFormFile? NewAvatar { get; set; }

        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }

        public string FullName => $"{FirstName} {LastName}".Trim();
    }

    public class AccountSecurityViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public bool TwoFactorEnabled { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public List<string> RecoveryCodes { get; set; } = new();
        public bool HasRecoveryCodes { get; set; }
        public List<UserLoginInfo> ExternalLogins { get; set; } = new();
        public string? AuthenticatorKey { get; set; }
        public List<string> TwoFactorProviders { get; set; } = new();
    }

    public class ChangePasswordFormViewModel
    {
        [Required(ErrorMessage = "Current password is required")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your new password")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class TwoFactorSetupViewModel
    {
        public string AuthenticatorKey { get; set; } = string.Empty;
        public string QrCodeUri { get; set; } = string.Empty;
        public string QrCodeImageData { get; set; } = string.Empty; // Base64 image data
        public string ManualEntryKey { get; set; } = string.Empty; // Formatted key for manual entry
        public List<string> RecoveryCodes { get; set; } = new();
        public bool IsEnabled { get; set; }

        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(7, ErrorMessage = "Verification code must be 6-7 characters", MinimumLength = 6)]
        public string VerificationCode { get; set; } = string.Empty;
    }

    public class NotificationSettingsViewModel
    {
        public bool EmailNotifications { get; set; } = true;
        public bool OrderUpdates { get; set; } = true;
        public bool BookRecommendations { get; set; } = false;
        public bool SecurityAlerts { get; set; } = true;
        public bool NewsletterSubscription { get; set; } = false;
        public bool SmsNotifications { get; set; } = false;
    }

    public class ConnectedAccountsViewModel
    {
        public List<UserLoginInfo> ExternalLogins { get; set; } = new();
        public List<string> AvailableProviders { get; set; } = new();
    }

    public class DeleteAccountViewModel
    {
        [Required(ErrorMessage = "Password is required to delete account")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm account deletion")]
        public bool ConfirmDeletion { get; set; }

        [Required(ErrorMessage = "Please type 'DELETE MY ACCOUNT' to confirm")]
        public string ConfirmationText { get; set; } = string.Empty;

        [Required(ErrorMessage = "You must acknowledge the consequences")]
        public bool UnderstandConsequences { get; set; }

        public string Reason { get; set; } = string.Empty;

        // Account summary data
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public int TotalOrders { get; set; }
        public int BooksAuthored { get; set; }
    }

    public class DownloadDataViewModel
    {
        public PersonalDataInfo PersonalData { get; set; } = new();
        public List<OrderInfo> Orders { get; set; } = new();
        public List<BookInfo> Books { get; set; } = new();
        public ActivityInfo Activity { get; set; } = new();
    }

    public class PersonalDataInfo
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
    }

    public class OrderInfo
    {
        public int OrderId { get; set; }
        public DateTime OrderDate { get; set; }
        public decimal Total { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> BookTitles { get; set; } = new();
    }

    public class BookInfo
    {
        public int BookId { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public decimal Price { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class ActivityInfo
    {
        public DateTime? LastLogin { get; set; }
        public int TotalOrders { get; set; }
        public int BooksAuthored { get; set; }
        public decimal TotalSpent { get; set; }
    }
}

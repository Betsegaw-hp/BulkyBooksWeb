using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace BulkyBooksWeb.Models.ViewModels
{
    public class UserManagementViewModel
    {
        public List<UserManagementItem> Users { get; set; } = new();
        public string SearchTerm { get; set; } = string.Empty;
        public string RoleFilter { get; set; } = string.Empty;
        public int CurrentPage { get; set; } = 1;
        public int TotalPages { get; set; }
        public int TotalUsers { get; set; }
        public List<string> AvailableRoles { get; set; } = new();
    }

    public class UserManagementItem
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string AvatarUrl { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new();
        public bool EmailConfirmed { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public int AccessFailedCount { get; set; }
        public bool TwoFactorEnabled { get; set; }
    }

    public class CreateUserViewModel
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        public string LastName { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Invalid phone number")]
        public string PhoneNumber { get; set; } = string.Empty;

        public IFormFile? Avatar { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm password")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;

        public List<string> SelectedRoles { get; set; } = new();
        public List<string> AvailableRoles { get; set; } = new();

        public bool EmailConfirmed { get; set; } = true;
        public bool TwoFactorEnabled { get; set; } = false;
        public bool LockoutEnabled { get; set; } = true;
        public bool SendWelcomeEmail { get; set; } = true;

        public string FullName => $"{FirstName} {LastName}".Trim();
    }

    public class EditUserViewModel
    {
        public string Id { get; set; } = string.Empty;

        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        public string LastName { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Invalid phone number")]
        public string PhoneNumber { get; set; } = string.Empty;

        public IFormFile? Avatar { get; set; }
        public string CurrentAvatarUrl { get; set; } = string.Empty;

        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmNewPassword { get; set; } = string.Empty;

        public List<string> CurrentRoles { get; set; } = new();
        public List<string> AvailableRoles { get; set; } = new();

        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }

        public string FullName => $"{FirstName} {LastName}".Trim();
    }

    public class UserDetailsViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string AvatarUrl { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new();
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public List<Book> Books { get; set; } = new();

        public string FullName => $"{FirstName} {LastName}".Trim();
    }

    public class UserActivityLog
    {
        public DateTime Timestamp { get; set; }
        public string Action { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
    }

    public class UserRoleManagementViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public List<string> CurrentRoles { get; set; } = new();
        public List<RoleAssignmentItem> AvailableRoles { get; set; } = new();
    }

    public class RoleAssignmentItem
    {
        public string RoleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsAssigned { get; set; }
    }

    public class BulkUserActionViewModel
    {
        public List<string> SelectedUserIds { get; set; } = new();
        public string Action { get; set; } = string.Empty; // Lock, Unlock, Delete, ChangeRole
        public string NewRole { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }

    public class UserSecurityViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public bool TwoFactorEnabled { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public List<string> RecoveryCodes { get; set; } = new();
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public List<UserLoginInfo> ExternalLogins { get; set; } = new();
    }

    public class ResetPasswordViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm password")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;

        public bool SendNotificationEmail { get; set; } = true;
    }

    public class ManageRolesViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string AvatarUrl { get; set; } = string.Empty;
        public List<string> CurrentRoles { get; set; } = new();
        public List<string> AllRoles { get; set; } = new();
        public List<string> SelectedRoles { get; set; } = new();
    }
}

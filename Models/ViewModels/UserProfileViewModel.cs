using System.ComponentModel.DataAnnotations;

namespace BulkyBooksWeb.Models.ViewModels
{
	public class UserProfileViewModel
	{
		public User User { get; set; } = new();
		public UpdateProfileViewModel UpdateProfile { get; set; } = new();
		public ChangePasswordViewModel ChangePassword { get; set; } = new();
		public UpdatePreferencesViewModel UpdatePreferences { get; set; } = new();
	}

	public class UpdateProfileViewModel
	{
		[Required(ErrorMessage = "Full name is required.")]
		public string FullName { get; set; } = string.Empty;

		[Required(ErrorMessage = "Email is required.")]
		[EmailAddress(ErrorMessage = "Invalid email address.")]
		public string Email { get; set; } = string.Empty;
	}

	public class ChangePasswordViewModel
	{
		[Required(ErrorMessage = "Current password is required.")]
		public string CurrentPassword { get; set; } = string.Empty;

		[Required(ErrorMessage = "New password is required.")]
		[MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")]
		public string NewPassword { get; set; } = string.Empty;

		[Required(ErrorMessage = "Confirm new password is required.")]
		[Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
		public string ConfirmNewPassword { get; set; } = string.Empty;
	}

	public class UpdatePreferencesViewModel
	{
		public bool EmailNotificationEnabled { get; set; }
		public bool ActivityAlertEnabled { get; set; }
		public int ItemsPerPage { get; set; } = 10;
	}
}
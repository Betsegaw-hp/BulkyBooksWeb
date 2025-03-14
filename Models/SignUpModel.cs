using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Models
{
	public class SignUpModel
	{
		[Required]
		[MaxLength(50)]
		[Remote("IsUsernameUnique", "Auth", ErrorMessage = "Username already exists.")]
		public string Username { get; set; } = string.Empty;

		[Required]
		public string Password { get; set; } = string.Empty;
		[Required]
		public string ConfirmPassword { get; set; } = string.Empty;
		public RoleOpt Role { get; set; } = RoleOpt.User;

		[EmailAddress]
		public string Email { get; set; } = string.Empty;
		public bool AcceptTerms { get; set; } = false;
		public string FullName { get; set; } = string.Empty;

	}
}

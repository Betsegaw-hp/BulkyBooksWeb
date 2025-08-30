using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Models
{
	public enum RoleOpt
	{
		Admin,
		Author,
		User
	}

	public class User 
	{
		[Key]
		public int Id { get; set; }

		[Required]
		[MaxLength(50)]
		[Remote("IsUsernameUnique", "Auth", ErrorMessage = "Username already exists.")]
		public string Username { get; set; } = string.Empty;

		[Required]
		public string PasswordHash { get; set; } = string.Empty; // Store hashed password

		public RoleOpt Role { get; set; } = RoleOpt.User; // Default role

		[Required]
		[EmailAddress]
		public string Email { get; set; } = string.Empty;

		public string FullName { get; set; } = string.Empty;

		public string AvatarUrl { get; set; } = string.Empty;

		public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
		public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

	}
}

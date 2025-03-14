using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Models
{
	public class LoginModel
	{
		[Required]
		[MaxLength(50)]
		public string Username { get; set; } = string.Empty;

		[Required]
		public string Password { get; set; } = string.Empty;

		public bool RememberMe { get; set; } = false;
		public string? ReturnUrl { get; set; } = string.Empty;
	}
}

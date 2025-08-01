using System.Security.Claims;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Data
{
	public interface IUserContext
	{
		string? GetCurrentUserId();
	}

	public class UserContext : IUserContext
	{
		private readonly IHttpContextAccessor _httpContextAccessor;

		public UserContext(IHttpContextAccessor httpContextAccessor)
		{
			_httpContextAccessor = httpContextAccessor;
		}

		public string? GetCurrentUserId()
		{
			return _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
		}
	}
}
using System.Security.Claims;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Data
{
	public interface IUserContext
	{
		int? GetCurrentUserId();
	}

	public class UserContext : IUserContext
	{
		private readonly IHttpContextAccessor _httpContextAccessor;

		public UserContext(IHttpContextAccessor httpContextAccessor)
		{
			_httpContextAccessor = httpContextAccessor;
		}

		public int? GetCurrentUserId()
		{
			var userIdClaim = _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (int.TryParse(userIdClaim, out int userId))
			{
				return userId;
			}

			return null;
		}
	}
}
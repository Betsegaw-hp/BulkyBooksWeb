using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Services
{
	public class UserService
	{
		private readonly ApplicationDbContext _db;

		public UserService(ApplicationDbContext applicationDbContext)
		{
			_db = applicationDbContext;
		}

		public async Task<User?> GetUserById(int id)
		{
			var legacyUser = await _db.LegacyUsers.FindAsync(id);
			return legacyUser;
		}

		public async Task<User?> GetUserByStringId(string id)
		{
			// Try to find the ApplicationUser first
			var applicationUser = await _db.Users.FindAsync(id);
			if (applicationUser != null)
			{
				// Convert ApplicationUser to User for backward compatibility
				return new User
				{
					Id = int.Parse(applicationUser.Id),
					Username = applicationUser.UserName ?? "",
					Email = applicationUser.Email ?? "",
					FullName = applicationUser.FullName,
					AvatarUrl = applicationUser.AvatarUrl,
					Role = GetRoleFromUser(applicationUser),
					CreatedAt = applicationUser.CreatedAt,
					UpdatedAt = applicationUser.UpdatedAt,
					PasswordHash = "" // Don't expose
				};
			}
			return null;
		}

		private RoleOpt GetRoleFromUser(ApplicationUser user)
		{
			// This would need to be enhanced to properly get roles from Identity
			// For now, return User as default
			return RoleOpt.User;
		}
	}
}
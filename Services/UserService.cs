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
			var user = await _db.Users.FindAsync(id);
			return user;
		}
	}
}
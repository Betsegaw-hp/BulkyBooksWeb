using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Services
{
	public class CategoryService
	{
		private readonly ApplicationDbContext _db;

		public CategoryService(ApplicationDbContext db)
		{
			_db = db;
		}

		public async Task<IEnumerable<Category>> GetAllCategoriesAsync()
		{
			return await _db.Categories.ToListAsync();
		}
	}
}

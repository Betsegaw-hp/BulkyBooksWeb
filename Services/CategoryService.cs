using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Dtos;

namespace BulkyBooksWeb.Services
{
	public class CategoryService
	{
		private readonly ApplicationDbContext _db;

		public CategoryService(ApplicationDbContext db)
		{
			_db = db;
		}

		public async Task<bool> IsCategoryNameUnique(string name)
		{
			return !await _db.Categories.AnyAsync(c => c.Name == name);
		}

		public async Task<IEnumerable<Category>> GetAllCategoriesAsync()
		{
			return await _db.Categories.ToListAsync();
		}

		public async Task<Category?> GetCategoryByIdAsync(int id)
		{
			var category = await _db.Categories.FindAsync(id);
			if (category == null)
			{
				return null;
			}
			return category;

		}
		public async Task CreateCategory(CreateCategoryDto createCategoryDto)
		{
			Category category = new()
			{
				Name = createCategoryDto.Name,
				DisplayOrder = createCategoryDto.DisplayOrder,
				CreatedDateTime = DateTime.Now,
				UpdatedDateTime = DateTime.Now
			};

			_db.Categories.Add(category);

			await _db.SaveChangesAsync();
		}

		public async Task UpdateCategory(int id, CreateCategoryDto editCategoryDto)
		{
			var existingCategory = await _db.Categories.FindAsync(id);
			if (existingCategory != null)
			{
				existingCategory.Name = editCategoryDto.Name;
				existingCategory.DisplayOrder = editCategoryDto.DisplayOrder;
				existingCategory.UpdatedDateTime = DateTime.Now;

				await _db.SaveChangesAsync();
			}
		}

		public async Task<bool> DeleteCategory(int id)
		{
			var category = await _db.Categories.FindAsync(id);
			if (category != null)
			{
				_db.Categories.Remove(category);
				await _db.SaveChangesAsync();
				return true;
			}
			return false;
		}

	}
}

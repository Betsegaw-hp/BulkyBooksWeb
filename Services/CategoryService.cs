using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models.ViewModels;

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

		public async Task<IEnumerable<Category>> GetAllCategories()
		{
			return await _db.Categories.ToListAsync();
		}

		public async Task<IEnumerable<CategoryViewModel>> GetAllCategoriesWithBookCount()
		{
			return await _db.Categories
				.Select(c => new CategoryViewModel
				{
					Id = c.Id,
					Name = c.Name,
					DisplayOrder = c.DisplayOrder,
					BookCount = _db.Books.Count(b => b.CategoryId == c.Id)
				})
				.ToListAsync();
		}

		public async Task<Category?> GetCategoryById(int id)
		{
			var category = await _db.Categories.Include(c => c.Books).FirstOrDefaultAsync(c => c.Id == id);
			return category;

		}
		public async Task CreateCategory(CreateCategoryDto createCategoryDto)
		{
			Category category = new()
			{
				Name = createCategoryDto.Name,
				DisplayOrder = createCategoryDto.DisplayOrder,
			};

			await _db.Categories.AddAsync(category);

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

		public async Task<bool> BulkDeleteCategories(int[] ids)
		{
			var categoriesToDelete = await _db.Categories.Where(c => ids.Contains(c.Id)).ToListAsync();
			if (categoriesToDelete.Any())
			{
				_db.Categories.RemoveRange(categoriesToDelete);
				await _db.SaveChangesAsync();
				return true;
			}
			return false;
		}


    }
}

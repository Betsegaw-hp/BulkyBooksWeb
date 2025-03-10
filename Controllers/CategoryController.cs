using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;

namespace BulkyBooksWeb.Controllers
{
	public class CategoryController(CategoryService categoryService) : Controller
	{
		private readonly CategoryService _categoryService = categoryService;

		public async Task<IActionResult> Index()
		{
			var categories = await _categoryService.GetAllCategoriesAsync();
			return View(categories);
		}
	}
}
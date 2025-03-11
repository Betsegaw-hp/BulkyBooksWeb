using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Dtos;

namespace BulkyBooksWeb.Controllers
{
	[Route("Category")]
	public class CategoryController(CategoryService categoryService) : Controller
	{
		private readonly CategoryService _categoryService = categoryService;

		[HttpGet]
		public async Task<IActionResult> Index()
		{
			var categories = await _categoryService.GetAllCategoriesAsync();
			return View(categories);
		}

		[HttpGet]
		[ActionName("Detail")]
		[Route("Category/Detail/{id:int}")]
		public async Task<IActionResult> Detail(int id)
		{
			var category = await _categoryService.GetCategoryByIdAsync(id);
			if (category == null)
			{
				return NotFound();
			}
			return View(category);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Create([FromForm] CreateCategoryDto createCategoryDto)
		{
			Console.WriteLine("Create method called with DTO: " + createCategoryDto.Name);
			if (ModelState.IsValid)
			{
				await _categoryService.CreateCategory(createCategoryDto);
				TempData["success"] = "Category created successfully";
			}
			else
			{
				TempData["error"] = "Failed to create category";
			}

			return RedirectToAction("Index");
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[Route("Edit/{id:int}")]
		public async Task<IActionResult> Edit(int id, [FromForm] CreateCategoryDto editCategoryDto)
		{
			Console.WriteLine("Edit method called with DTO: " + editCategoryDto.Name);
			if (ModelState.IsValid)
			{
				await _categoryService.UpdateCategory(id, editCategoryDto);
				TempData["success"] = "Category updated successfully";
			}
			else
			{
				TempData["error"] = "Failed to update category";
			}

			return RedirectToAction("Detail", new { id });
		}

		[HttpPost]
		[Route("Delete/{id:int}")]
		public async Task<IActionResult> Delete(int id)
		{
			Console.WriteLine("Delete method called for ID: " + id);
			var result = await _categoryService.DeleteCategory(id);
			if (result)
				TempData["success"] = "Category deleted successfully";
			else
				TempData["error"] = "Failed to delete category";

			return RedirectToAction("Index");
		}

	}
}
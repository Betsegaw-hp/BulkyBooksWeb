using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Controllers
{
	[Authorize(Roles = "admin, author")]
	[Route("[controller]")]
	public class CategoryController(CategoryService categoryService) : Controller
	{
		private readonly CategoryService _categoryService = categoryService;

		[HttpGet]
		public async Task<IActionResult> Index()
		{
			var categories = await _categoryService.GetAllCategories();
			return View(categories);
		}

		[HttpGet]
		[ActionName("Detail")]
		[Route("Detail/{id:int}")]
		public async Task<IActionResult> Detail(int id)
		{
			Category? category = await _categoryService.GetCategoryById(id);
			if (category == null)
			{
				return NotFound();
			}
			return View(category);
		}

		[HttpGet]
		[ActionName("IsCategoryNameUnique")]
		[Route("IsCategoryNameUnique")]
		public async Task<IActionResult> IsCategoryNameUnique([FromQuery] string name)
		{
			var isUnique = await _categoryService.IsCategoryNameUnique(name);
			if (string.IsNullOrEmpty(name) || isUnique)
				return Json(true);
			return Json(false);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Create([FromForm] CreateCategoryDto createCategoryDto)
		{
			Console.WriteLine("Create method called with DTO: " + createCategoryDto.Name);

			if (string.IsNullOrEmpty(createCategoryDto.Name))
				ModelState.AddModelError("Name", "Category name is required.");

			var isUnique = await _categoryService.IsCategoryNameUnique(createCategoryDto.Name);
			if (!isUnique)
				ModelState.AddModelError("Name", $"Category name '{createCategoryDto.Name}' already exists.");

			if (createCategoryDto.DisplayOrder < 1 || createCategoryDto.DisplayOrder > 100)
				ModelState.AddModelError("DisplayOrder", "Display Order must be between 1 and 100.");


			if (ModelState.IsValid)
			{
				await _categoryService.CreateCategory(createCategoryDto);
				TempData["success"] = "Category created successfully";
			}
			else
				TempData["error"] = "Failed to create category";

			return RedirectToAction("Index");
		}

		[Authorize(Policy = "AdminOnly")]
		[HttpPost("Edit/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Edit(int id, [FromForm] CreateCategoryDto editCategoryDto)
		{
			Console.WriteLine("Edit method called with DTO: " + editCategoryDto.Name);
			var isUnique = await _categoryService.IsCategoryNameUnique(editCategoryDto.Name);
			if (!isUnique)
				ModelState.AddModelError("Name", $"Category name '{editCategoryDto.Name}' already exists.");

			if (ModelState.IsValid)
			{
				await _categoryService.UpdateCategory(id, editCategoryDto);
				TempData["success"] = "Category updated successfully";
			}
			else
				TempData["error"] = "Failed to update category";

			return RedirectToAction("Detail", new { id });
		}

		[Authorize(Policy = "AdminOnly")]
		[HttpPost("Delete/{id:int}")]
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

		[Authorize(Policy = "AdminOnly")]
		[HttpPost("BulkDelete")]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> BulkDelete([FromForm] int[] selectedCategoryIds)
        {
            Console.WriteLine(selectedCategoryIds);

            if (selectedCategoryIds == null || selectedCategoryIds.Length == 0)
            {
                TempData["error"] = "No categories selected for deletion.";
                return RedirectToAction("Index");
            }

			var result = await _categoryService.BulkDeleteCategories(selectedCategoryIds);
			if (result)
				TempData["success"] = "Categories deleted successfully.";
			else
				TempData["error"] = "Failed to delete categories.";

            return RedirectToAction("Index");
        }

	}
}
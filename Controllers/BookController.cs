using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models.ViewModels;

namespace BulkyBooksWeb.Controllers
{
	[Route("[controller]")]
	public class BookController : Controller
	{
		private readonly BookService _bookService;
		private readonly CategoryService _categoryService;

		public BookController(BookService bookService, CategoryService categoryService)
		{
			_bookService = bookService;
			_categoryService = categoryService;
		}

		[HttpGet]
		public async Task<IActionResult> Index()
		{
			var books = await _bookService.GetAllBooks();
			return View(books);
		}

		[HttpGet("IsISBNUnique")]
		public async Task<IActionResult> IsISBNUnique(string isbn, int id)
		{
			return Json(await _bookService.IsISBNUnique(isbn, id));
			// return Json(false);
		}

		[HttpGet("{id:int}")]
		public async Task<IActionResult> Detail(int id)
		{
			Book? book = await _bookService.GetBookById(id);
			if (book == null)
			{
				return NotFound();
			}
			return View(book);
		}

		[HttpGet("Create")]
		public async Task<IActionResult> Create()
		{
			IEnumerable<Category> categories = await _categoryService.GetAllCategories();

			BookCreateViewModel bookViewModel = new BookCreateViewModel()
			{
				Categories = categories,
				CreateBookDto = new CreateBookDto()
			};

			return View(bookViewModel);
		}

		[HttpPost("Create")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Create([FromForm] CreateBookDto createBookDto)
		{
			if (ModelState.IsValid)
			{
				await _bookService.CreateBook(createBookDto);
				return RedirectToAction(nameof(Index));
			}
			return View(createBookDto);
		}

		[HttpGet("Edit/{id:int}")]
		public async Task<IActionResult> Edit(int id)
		{
			if (id <= 0) return NotFound();

			Book? book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			BookUpdateViewModel bookViewModel = new BookUpdateViewModel()
			{
				Categories = await _categoryService.GetAllCategories(),
				UpdateBookDto = new UpdateBookDto()
				{
					Id = book.Id,
					Title = book.Title,
					ISBN = book.ISBN,
					Author = book.Author,
					Price = book.Price,
					Description = book.Description,
					// CoverImageUrl = book.CoverImageUrl,
					CategoryId = book.CategoryId,
				}
			};

			return View(bookViewModel);
		}

		[HttpPost("Edit/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Edit(int id, [FromForm] UpdateBookDto updateBookDto)
		{
			Console.WriteLine(updateBookDto.CategoryId);
			if (ModelState.IsValid)
			{
				await _bookService.UpdateBook(id, updateBookDto);
				return RedirectToAction(nameof(Index));
			}
			else
			{
				// Log errors: check why CategoryId is 0
				var errors = ModelState.Values.SelectMany(v => v.Errors);
				Console.WriteLine("ModelState errors:");
				foreach (var error in errors)
				{
					Console.WriteLine(error?.ErrorMessage);
				}
				return View(updateBookDto);
			}
		}

		[HttpPost("Delete/{id:int}")]
		public async Task<IActionResult> Delete(int id)
		{
			if (id <= 0) return NotFound();

			Book? book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			return View(book);
		}
	}
}
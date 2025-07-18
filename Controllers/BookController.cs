using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using BulkyBooksWeb.Policies;
using BulkyBooksWeb.Data;
using Microsoft.AspNetCore.Http.HttpResults;

namespace BulkyBooksWeb.Controllers
{

	[Authorize(Roles = "admin, author, user")]
	[Route("[controller]")]
	public class BookController : Controller
	{
		private readonly BookService _bookService;
		private readonly CategoryService _categoryService;
		private readonly IAuthorizationService _authorizationService;
		private readonly IUserContext _userContext;


		public BookController(
			BookService bookService,
			CategoryService categoryService,
			IAuthorizationService authorizationService,
			IUserContext userContext)
		{
			_bookService = bookService;
			_categoryService = categoryService;
			_authorizationService = authorizationService;
			_userContext = userContext;
		}

		[Authorize(Roles = "admin, author")]
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

		[Authorize(Roles = "admin, author")]
		[HttpGet("Create")]
		public async Task<IActionResult> Create()
		{
			IEnumerable<Category> categories = await _categoryService.GetAllCategories();

			BookCreateViewModel bookViewModel = new()
			{
				Categories = categories,
				CreateBookDto = new CreateBookDto()
			};

			return View(bookViewModel);
		}

		[Authorize(Roles = "admin, author")]
		[HttpPost("Create")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Create([FromForm] CreateBookDto createBookDto)
		{
			if (ModelState.IsValid)
			{
				var authorId = _userContext.GetCurrentUserId();
				if (authorId != null)
				{
					Console.WriteLine("Author ID: " + authorId);
					await _bookService.CreateBook(createBookDto, (int)authorId);
					return RedirectToAction(nameof(Index));
				}

				return BadRequest("Author ID is null.");
			}
			return View(createBookDto);
		}

		[Authorize(Roles = "admin, author")]
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
					Price = book.Price,
					Description = book.Description,
					CoverImageUrl = book.CoverImageUrl,
					CategoryId = book.CategoryId,
				}
			};

			return View(bookViewModel);
		}

		[Authorize(Roles = "admin, author")]
		[HttpPost("Edit/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Edit(int id, [FromForm] UpdateBookDto updateBookDto)
		{
			if (id != updateBookDto.Id || id <= 0) return NotFound();

			var book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			var authResult = await _authorizationService.AuthorizeAsync(User, book.AuthorId, new BookOwnerOrAdminRequirement());
			if (!authResult.Succeeded)
				return Forbid();

			Console.WriteLine(updateBookDto.CategoryId);
			if (ModelState.IsValid)
			{
				await _bookService.UpdateBook(id, updateBookDto);
				return RedirectToAction(nameof(Index));
			}
			else
			{
				var errors = ModelState.Values.SelectMany(v => v.Errors);
				Console.WriteLine("ModelState errors:");
				foreach (var error in errors)
				{
					Console.WriteLine(error?.ErrorMessage);
				}
				return View(updateBookDto);
			}
		}

		[Authorize(Roles = "admin, author")]
		[HttpPost("Delete/{id:int}")]
		public async Task<IActionResult> Delete(int id)
		{
			if (id <= 0) return NotFound();

			Book? book = await _bookService.GetBookById(id);
			if (book == null) return Ok();  // if the book doesn't exist, the job is done ;)

			var authResult = await _authorizationService.AuthorizeAsync(User, book.AuthorId, new BookOwnerOrAdminRequirement());
			if (!authResult.Succeeded)
				return Forbid();
			await _bookService.DeleteBook(id);

			return RedirectToAction(nameof(Index));
		}
	}
}
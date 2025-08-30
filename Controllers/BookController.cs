using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using BulkyBooksWeb.Policies;
using BulkyBooksWeb.Data;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;

namespace BulkyBooksWeb.Controllers
{

	[Authorize(Roles = "Admin, Author, User")]
	[Route("[controller]")]
	public class BookController : Controller
	{
			private readonly BookService _bookService;
			private readonly CategoryService _categoryService;
			private readonly IAuthorizationService _authorizationService;
			private readonly IUserContext _userContext;
			private readonly UserManager<ApplicationUser> _userManager;


			public BookController(
				BookService bookService,
				CategoryService categoryService,
				IAuthorizationService authorizationService,
				IUserContext userContext,
				UserManager<ApplicationUser> userManager)
			{
				_bookService = bookService;
				_categoryService = categoryService;
				_authorizationService = authorizationService;
				_userContext = userContext;
				_userManager = userManager;
			}

		[Authorize(Roles = "Admin, Author")]
		[HttpGet]
		public async Task<IActionResult> Index()
		{
			IEnumerable<Book> books;
			
			if (User.IsInRole("Admin"))
			{
				// Admin sees all books
				books = await _bookService.GetAllBooks();
			}
			else if (User.IsInRole("Author"))
			{
				// Author sees only their own books
				var authorId = _userContext.GetCurrentUserId();
				if (authorId == null)
				{
					return BadRequest("Unable to identify the current user.");
				}
				books = await _bookService.GetBooksByAuthor(authorId);
			}
			else
			{
				return Forbid();
			}
			
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

		[Authorize(Roles = "Admin, Author")]
		[HttpGet("Create")]
		public async Task<IActionResult> Create()
		{
			if (User.IsInRole("Author"))
			{
				var user = await _userManager.GetUserAsync(User);
				if (user == null || user.KycStatus != KycStatus.Verified)
				{
					TempData["Error"] = "You must complete and verify your KYC before uploading books.";
					return RedirectToAction("Index", "Kyc");
				}
			}
			IEnumerable<Category> categories = await _categoryService.GetAllCategories();

			BookCreateViewModel bookViewModel = new()
			{
				Categories = categories,
				CreateBookDto = new CreateBookDto()
			};

			return View(bookViewModel);
		}

		[Authorize(Roles = "Admin, Author")]
		[HttpPost("Create")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Create([FromForm] CreateBookDto createBookDto)
		{
			if (User.IsInRole("Author"))
			{
				var user = await _userManager.GetUserAsync(User);
				if (user == null || user.KycStatus != KycStatus.Verified)
				{
					TempData["Error"] = "You must complete and verify your KYC before uploading books.";
					return RedirectToAction("Index", "Kyc");
				}
			}
			if (ModelState.IsValid)
			{
				var authorId = _userContext.GetCurrentUserId();
				if (authorId != null)
				{
					Console.WriteLine("Author ID: " + authorId);
					await _bookService.CreateBook(createBookDto, authorId);
					return RedirectToAction(nameof(Index));
				}

				return BadRequest("Author ID is null.");
			}
			return View(createBookDto);
		}

		[Authorize(Roles = "Admin, Author")]
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
					IsFeatured = book.IsFeatured
				}
			};

			return View(bookViewModel);
		}

		[Authorize(Roles = "Admin, Author")]
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

		[Authorize(Roles = "Admin, Author")]
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

		[Authorize(Roles = "Admin")]
		[HttpPost("ToggleFeatured/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ToggleFeatured(int id)
		{
			var book = await _bookService.GetBookById(id);
			if (book == null)
			{
				return Json(new { success = false, message = "Book not found" });
			}

			var newFeaturedStatus = !book.IsFeatured;
			var success = await _bookService.SetBookFeaturedStatus(id, newFeaturedStatus);
			if (success)
			{
				return Json(new 
				{ 
					success = true, 
					isFeatured = newFeaturedStatus,
					message = newFeaturedStatus ? "Book marked as featured" : "Book removed from featured"
				});
			}

			return Json(new { success = false, message = "Failed to update featured status" });
		}
	}
}
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
					return RedirectToAction("Submit", "Kyc");
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
		public async Task<IActionResult> Create([FromForm] BookCreateViewModel viewModel)
		{
			if (User.IsInRole("Author"))
			{
				var user = await _userManager.GetUserAsync(User);
				if (user == null || user.KycStatus != KycStatus.Verified)
				{
					TempData["Error"] = "You must complete and verify your KYC before uploading books.";
					return RedirectToAction("Submit", "Kyc");
					// return Forbid();
				}
			}
			
			// Add debugging for validation issues
			if (!ModelState.IsValid)
			{
				var errors = ModelState.Values.SelectMany(v => v.Errors);
				Console.WriteLine("ModelState errors in Create:");
				foreach (var error in errors)
				{
					Console.WriteLine($"Error: {error?.ErrorMessage}");
				}
				foreach (var modelError in ModelState)
				{
					Console.WriteLine($"Key: {modelError.Key}, Errors: {string.Join(", ", modelError.Value.Errors.Select(e => e.ErrorMessage))}");
				}
			}
			
			if (ModelState.IsValid)
			{
				var authorId = _userContext.GetCurrentUserId();
				if (authorId != null)
				{
					Console.WriteLine("Author ID: " + authorId);
					await _bookService.CreateBook(viewModel.CreateBookDto, authorId);
					TempData["Message"] = "Book created successfully!";
					return RedirectToAction(nameof(Index));
				}

				return BadRequest("Author ID is null.");
			}
			
			// If we reach here, there are validation errors
			// Repopulate the Categories for the dropdown
			viewModel.Categories = await _categoryService.GetAllCategories();
			return View(viewModel);
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
			CurrentPdfFilePath = book.PdfFilePath,
			CurrentCoverImagePath = book.CoverImagePath,
			UpdateBookDto = new UpdateBookDto()
			{
				Id = book.Id,
				Title = book.Title,
				ISBN = book.ISBN,
				Price = book.Price,
				Description = book.Description,
				CategoryId = book.CategoryId,
				IsFeatured = book.IsFeatured
			}
		};

		return View(bookViewModel);
	}

	[Authorize(Roles = "Admin, Author")]
	[HttpPost("Edit/{id:int}")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Edit(int id, [FromForm] BookUpdateViewModel viewModel)
		{
			if (id != viewModel.UpdateBookDto.Id || id <= 0) return NotFound();

			var book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			var authResult = await _authorizationService.AuthorizeAsync(User, book.AuthorId, new BookOwnerOrAdminRequirement());
			if (!authResult.Succeeded)
				return Forbid();

			Console.WriteLine(viewModel.UpdateBookDto.CategoryId);
			if (ModelState.IsValid)
			{
			// Check for significant changes before updating
			bool pdfChanged = viewModel.UpdateBookDto.PdfFile != null;
			bool coverImageChanged = viewModel.UpdateBookDto.CoverImageFile != null;
			bool hasSignificantChanges = await _bookService.CheckAndMarkSignificantChanges(id, viewModel.UpdateBookDto, pdfChanged, coverImageChanged);
			
			await _bookService.UpdateBook(id, viewModel.UpdateBookDto, viewModel.UpdateBookDto.PdfFile, viewModel.UpdateBookDto.CoverImageFile);				if (hasSignificantChanges && (book.Status == BookStatus.Approved || book.Status == BookStatus.Published))
				{
					TempData["Message"] = "Book updated successfully. Due to significant changes, it has been automatically resubmitted for review.";
				}
				else if (hasSignificantChanges)
				{
					TempData["Message"] = "Book updated successfully. Significant changes detected - please review before submission.";
				}
				else
				{
					TempData["Message"] = "Book updated successfully.";
				}
				
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
				
				// Repopulate the view model for display
				viewModel.Categories = await _categoryService.GetAllCategories();
				viewModel.CurrentPdfFilePath = book.PdfFilePath;
				viewModel.CurrentCoverImagePath = book.CoverImagePath;
				
				return View(viewModel);
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

		[Authorize(Roles = "Author")]
		[HttpPost("SubmitForReview/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SubmitForReview(int id)
		{
			var book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			var authorId = _userContext.GetCurrentUserId();
			if (book.AuthorId != authorId && !User.IsInRole("Admin"))
			{
				return Forbid();
			}

			await _bookService.SubmitBookForReview(id);
			TempData["Message"] = "Book submitted for review successfully.";
			return RedirectToAction("Index");
		}

		[Authorize(Roles = "Author")]
		[HttpPost("ResubmitForReview/{id:int}")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResubmitForReview(int id)
		{
			var book = await _bookService.GetBookById(id);
			if (book == null) return NotFound();

			var authorId = _userContext.GetCurrentUserId();
			if (book.AuthorId != authorId && !User.IsInRole("Admin"))
			{
				return Forbid();
			}

			await _bookService.ResubmitBookForReview(id);
			TempData["Message"] = "Book resubmitted for review successfully.";
			return RedirectToAction("Index");
		}

		[HttpGet("ReviewStatus")]
		[Authorize(Roles = "Author")]
		public async Task<IActionResult> ReviewStatus()
		{
			var userId = _userContext.GetCurrentUserId();
			if (string.IsNullOrEmpty(userId))
			{
				return Unauthorized();
			}
			
			var books = await _bookService.GetBooksByAuthor(userId);
			
			return View(books);
		}
	}
}
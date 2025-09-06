using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Services;

namespace BulkyBooksWeb.Controllers
{
    [Authorize(Roles = "Admin")]
    public class BookReviewAdminController : Controller
    {
        private readonly BookService _bookService;
        private readonly UserManager<ApplicationUser> _userManager;

        public BookReviewAdminController(BookService bookService, UserManager<ApplicationUser> userManager)
        {
            _bookService = bookService;
            _userManager = userManager;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return RedirectToAction("Dashboard");
        }

        [HttpGet]
        public async Task<IActionResult> Dashboard()
        {
            var pendingBooks = await _bookService.GetBooksByStatus(BookStatus.UnderReview);
            var resubmittedBooks = await _bookService.GetBooksByStatus(BookStatus.ResubmittedForReview);
            var allPendingBooks = pendingBooks.Concat(resubmittedBooks);
            var approvedBooks = await _bookService.GetBooksByStatus(BookStatus.Approved);
            var rejectedBooks = await _bookService.GetBooksByStatus(BookStatus.Rejected);
            var publishedBooks = await _bookService.GetBooksByStatus(BookStatus.Published);

            ViewBag.PendingCount = pendingBooks.Count();
            ViewBag.ResubmittedCount = resubmittedBooks.Count();
            ViewBag.ApprovedCount = approvedBooks.Count();
            ViewBag.RejectedCount = rejectedBooks.Count();
            ViewBag.PublishedCount = publishedBooks.Count();

            return View(allPendingBooks);
        }

        [HttpGet]
        public async Task<IActionResult> Pending()
        {
            var pendingBooks = await _bookService.GetBooksByStatus(BookStatus.UnderReview);
            var resubmittedBooks = await _bookService.GetBooksByStatus(BookStatus.ResubmittedForReview);
            var allPendingBooks = pendingBooks.Concat(resubmittedBooks);
            return View(allPendingBooks);
        }

        [HttpGet]
        public async Task<IActionResult> Review(int id)
        {
            var book = await _bookService.GetBookById(id);
            if (book == null) return NotFound();
            return View(book);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Approve(int id, string? comments)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                await _bookService.ApproveBook(id, user.Id, comments);
                TempData["Message"] = "Book approved successfully.";
            }
            return RedirectToAction("Dashboard");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Reject(int id, string? comments)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                await _bookService.RejectBook(id, user.Id, comments);
                TempData["Message"] = "Book rejected.";
            }
            return RedirectToAction("Dashboard");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Publish(int id)
        {
            await _bookService.PublishBook(id);
            TempData["Message"] = "Book published successfully.";
            return RedirectToAction("Dashboard");
        }

        [HttpGet]
        public async Task<IActionResult> FilterBooks(string status)
        {
            IEnumerable<Book> books;
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<BookStatus>(status, out var bookStatus))
            {
                books = await _bookService.GetBooksByStatus(bookStatus);
            }
            else
            {
                books = await _bookService.GetAllBooks();
            }
            return PartialView("_BookReviewTable", books);
        }
    }
}

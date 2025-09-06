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
        private readonly IMailgunEmailService _emailService;
        private readonly IWebHostEnvironment _env;

        public BookReviewAdminController(BookService bookService, UserManager<ApplicationUser> userManager, IMailgunEmailService emailService, IWebHostEnvironment env)
        {
            _bookService = bookService;
            _userManager = userManager;
            _emailService = emailService;
            _env = env;
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
        private async Task SendBookStatusEmail(Book book, string statusTitle, string statusMessage, string? adminComments)
        {
            if (book != null && book.Author != null && !string.IsNullOrEmpty(book.Author.Email))
            {
                var templatePath = Path.Combine(_env.WebRootPath, "EmailTemplates", "BookStatus.html");
                var template = System.IO.File.ReadAllText(templatePath);
                var html = template
                    .Replace("{{StatusTitle}}", statusTitle)
                    .Replace("{{FullName}}", book.Author.FullName ?? "Author")
                    .Replace("{{BookTitle}}", book.Title)
                    .Replace("{{StatusMessage}}", statusMessage)
                    .Replace("{{AdminComments}}", string.IsNullOrEmpty(adminComments) ? "" : adminComments);
                await _emailService.SendEmailAsync(book.Author.Email, $"Book {statusTitle}: {book.Title}", html);
            }
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
                var book = await _bookService.GetBookById(id);
                if (book != null)
                {
                    await SendBookStatusEmail(book, "Approved", "has been approved by the admin", comments);
                }
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
                var book = await _bookService.GetBookById(id);
                if (book != null)
                {
                    await SendBookStatusEmail(book, "Rejected", "was rejected by the admin", comments);
                }
            }
            return RedirectToAction("Dashboard");
        }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Publish(int id)
        {
            await _bookService.PublishBook(id);
            TempData["Message"] = "Book published successfully.";
            var book = await _bookService.GetBookById(id);
            if (book != null)
            {
                await SendBookStatusEmail(book, "Published", "is now published and available to customers", null);
            }
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

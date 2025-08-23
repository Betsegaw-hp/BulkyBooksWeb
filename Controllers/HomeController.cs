using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Services;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models.ViewModels;
using BulkyBooksWeb.Extensions;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace BulkyBooksWeb.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly BookService _bookService;
    private readonly CategoryService _categoryService;
    private readonly ICartService _cartService;

    public HomeController(ILogger<HomeController> logger, BookService bookService, CategoryService categoryService, ICartService cartService)
    {
        _logger = logger;
        _bookService = bookService;
        _categoryService = categoryService;
        _cartService = cartService;
    }


    public async Task<IActionResult> Index(string searchQuery, int[] categoryIds, decimal? minPrice, decimal? maxPrice, string sortOption = "newest", bool showFeaturedOnly = false, int page = 1)
    {
        int pageSize = 9;

        var filter = new FilterViewModel
        {
            SearchQuery = searchQuery,
            CategoryIds = categoryIds,
            MinPrice = minPrice,
            MaxPrice = maxPrice,
            SortOption = sortOption,
            ShowFeaturedOnly = showFeaturedOnly
        };

        var booksQuery = _bookService.GetBooksQuery();

        // Apply search filter
        if (!string.IsNullOrEmpty(searchQuery))
        {
            booksQuery = booksQuery.Where(b =>
                b.Title.Contains(searchQuery) ||
                (b.Author != null && b.Author.UserName != null && b.Author.UserName.Contains(searchQuery)) ||
                b.Description.Contains(searchQuery) ||
                b.ISBN.Contains(searchQuery));
        }

        // Apply category filter
        if (categoryIds != null && categoryIds.Length > 0)
        {
            booksQuery = booksQuery.Where(b => categoryIds.Contains(b.CategoryId));
        }

        // Apply featured filter
        if (showFeaturedOnly)
        {
            booksQuery = booksQuery.Where(b => b.IsFeatured);
        }

        // Apply price filters
        if (minPrice.HasValue)
        {
            booksQuery = booksQuery.Where(b => b.Price >= minPrice.Value);
        }

        if (maxPrice.HasValue)
        {
            booksQuery = booksQuery.Where(b => b.Price <= maxPrice.Value);
        }

        int totalBooks = await booksQuery.CountAsync();

        // Apply sorting
        switch (sortOption)
        {
            case "price_asc":
                booksQuery = booksQuery.OrderBy(b => b.Price);
                break;
            case "price_desc":
                booksQuery = booksQuery.OrderByDescending(b => b.Price);
                break;
            case "title_asc":
                booksQuery = booksQuery.OrderBy(b => b.Title);
                break;
            case "title_desc":
                booksQuery = booksQuery.OrderByDescending(b => b.Title);
                break;
            case "newest":
            default:
                booksQuery = booksQuery.OrderByDescending(b => b.Id); // Assuming Id increases with newer books
                break;
        }

        // Apply pagination
        var books = await booksQuery
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        int totalPages = (int)Math.Ceiling(totalBooks / (double)pageSize);

        var featuredBooks = await _bookService.GetFeaturedBooks(6); // Get top 6 featured books

        var allCategories = await _categoryService.GetAllCategoriesWithBookCount();

        var featuredCategories = allCategories
            .OrderByDescending(c => c.DisplayOrder)
            .Take(8)
            .ToList();

        // Create the view model
        var model = new BookListViewModel
        {
            Books = books,
            FeaturedBooks = featuredBooks,
            FeaturedCategories = featuredCategories,
            AllCategories = allCategories,
            CurrentFilter = filter,
            CurrentPage = page,
            TotalPages = totalPages,
            TotalBooks = totalBooks
        };

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> SearchBooks(string searchQuery, int[] categoryIds, decimal? minPrice, decimal? maxPrice, string sortOption = "newest", int page = 1)
    {
        int pageSize = 9;

        var filter = new FilterViewModel
        {
            SearchQuery = searchQuery,
            CategoryIds = categoryIds,
            MinPrice = minPrice,
            MaxPrice = maxPrice,
            SortOption = sortOption
        };

        var booksQuery = _bookService.GetBooksQuery();

        // Apply search filter
        if (!string.IsNullOrEmpty(searchQuery))
        {
            booksQuery = booksQuery.Where(b =>
                b.Title.Contains(searchQuery) ||
                (b.Author != null && b.Author.UserName != null && b.Author.UserName.Contains(searchQuery)) ||
                b.Description.Contains(searchQuery) ||
                b.ISBN.Contains(searchQuery));
        }

        // Apply category filter
        if (categoryIds != null && categoryIds.Length > 0)
        {
            booksQuery = booksQuery.Where(b => categoryIds.Contains(b.CategoryId));
        }

        // Apply price filters
        if (minPrice.HasValue)
        {
            booksQuery = booksQuery.Where(b => b.Price >= minPrice.Value);
        }

        if (maxPrice.HasValue)
        {
            booksQuery = booksQuery.Where(b => b.Price <= maxPrice.Value);
        }

        int totalBooks = await booksQuery.CountAsync();

        // Apply sorting
        switch (sortOption)
        {
            case "price_asc":
                booksQuery = booksQuery.OrderBy(b => b.Price);
                break;
            case "price_desc":
                booksQuery = booksQuery.OrderByDescending(b => b.Price);
                break;
            case "title_asc":
                booksQuery = booksQuery.OrderBy(b => b.Title);
                break;
            case "title_desc":
                booksQuery = booksQuery.OrderByDescending(b => b.Title);
                break;
            case "newest":
            default:
                booksQuery = booksQuery.OrderByDescending(b => b.Id);
                break;
        }

        // Apply pagination
        var books = await booksQuery
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        int totalPages = (int)Math.Ceiling(totalBooks / (double)pageSize);

        var result = new
        {
            books = books.Select(b => new
            {
                id = b.Id,
                title = b.Title,
                price = b.Price,
                coverImageUrl = b.CoverImageUrl,
                authorName = b.Author?.FullName,
                categoryName = b.Category?.Name,
                description = b.Description?.Length > 100 ? b.Description.Substring(0, 100) + "..." : b.Description
            }),
            totalPages = totalPages,
            currentPage = page,
            totalBooks = totalBooks
        };

        return Json(result);
    }

    [HttpGet]
    public async Task<IActionResult> GetCartCount()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return Json(new { count = 0 });
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Json(new { count = 0 });
        }

        var totalItems = await _cartService.GetCartCountAsync(userId);
        return Json(new { count = totalItems });
    }

    [Authorize(Roles = "User,Admin,Author")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddToCart(int id)
    {
        var book = await _bookService.GetBookById(id);
        if (book == null)
        {
            return NotFound();
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        // Migrate session cart to user cart if exists
        var sessionCart = HttpContext.Session.Get<List<CartItemDTO>>("Cart");
        if (sessionCart != null && sessionCart.Any())
        {
            await _cartService.MigrateSessionCartToUserAsync(sessionCart, userId);
            HttpContext.Session.Remove("Cart");
        }

        // Add to user's cart
        var cartItem = await _cartService.AddToCartAsync(userId, id, 1);
        if (cartItem == null)
        {
            return BadRequest("Failed to add book to cart");
        }

        // Check if this is an AJAX request
        if (Request.Headers["X-Requested-With"] == "XMLHttpRequest" || 
            Request.Headers["Content-Type"].ToString().Contains("application/json") ||
            Request.Query.ContainsKey("ajax"))
        {
            var totalItems = await _cartService.GetCartCountAsync(userId);
            return Json(new { 
                success = true, 
                message = "Book added to cart successfully!",
                cartCount = totalItems,
                bookTitle = book.Title
            });
        }

        TempData["Success"] = "Book added to cart successfully!";
        return RedirectToAction("Index", "Checkout");
    }

    [Authorize(Roles = "User,Admin,Author")]
    public IActionResult RemoveFromCart(int id)
    {
        var cart = HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? new List<CartItemDTO>();

        var cartItem = cart.FirstOrDefault(i => i.BookId == id);
        if (cartItem != null)
        {
            cart.Remove(cartItem);
            HttpContext.Session.Set("Cart", cart);
            TempData["Success"] = "Book removed from cart successfully!";
        }

        return RedirectToAction("Index", "Checkout");
    }

    [Authorize(Roles = "User,Admin,Author")]
    public IActionResult UpdateCart(int id, [FromQuery] int Quantity)
    {
        var cart = HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? new List<CartItemDTO>();

        var cartItem = cart.FirstOrDefault(i => i.BookId == id);
        if (cartItem != null)
        {
            if (Quantity <= 0)
            {
                cart.Remove(cartItem);
            }
            else
            {
                cartItem.Quantity = Quantity;
            }
            HttpContext.Session.Set("Cart", cart);
        }

        return RedirectToAction("Index", "Checkout");
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

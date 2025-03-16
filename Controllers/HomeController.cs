using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Services;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models.ViewModels;
using BulkyBooksWeb.Extensions;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly BookService _bookService;
    private readonly CategoryService _categoryService;

    public HomeController(ILogger<HomeController> logger, BookService bookService, CategoryService categoryService)
    {
        _logger = logger;
        _bookService = bookService;
        _categoryService = categoryService;
    }


    public async Task<IActionResult> Index(string searchQuery, int[] categoryIds, decimal? minPrice, decimal? maxPrice, string sortOption = "newest", int page = 1)
    {
        // Set page size
        int pageSize = 9;

        // Create filter view model
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
                b.Author.Username.Contains(searchQuery) ||
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

        // Get total count before pagination
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

        // Calculate total pages
        int totalPages = (int)Math.Ceiling(totalBooks / (double)pageSize);

        // Get featured books (e.g., books marked as featured or most popular)
        var featuredBooks = await _bookService.GetFeaturedBooks(6); // Get top 6 featured books

        // Get all categories for the filter sidebar
        var allCategories = await _categoryService.GetAllCategoriesWithBookCount();

        // Get featured categories (e.g., categories with most books)
        var featuredCategories = allCategories
            .OrderByDescending(c => c.BookCount)
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

    [Authorize(Roles = "user,admin,author")]
    [HttpPost]
    public async Task<IActionResult> AddToCart(int id)
    {
        var book = await _bookService.GetBookById(id);
        if (book == null)
        {
            return NotFound();
        }

        var cart = HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? new List<CartItemDTO>();

        // Find the cart item or create a new one
        var cartItem = cart.FirstOrDefault(i => i.BookId == id);
        if (cartItem != null)
        {
            cartItem.Quantity++;
        }
        else
        {
            cart.Add(new CartItemDTO { BookId = id, Title = book.Title, Price = book.Price, Quantity = 1 });
        }

        HttpContext.Session.Set("Cart", cart);

        TempData["Success"] = "Book added to cart successfully!";
        return RedirectToAction("Index", "Checkout");
    }

    [Authorize(Roles = "user,admin,author")]
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

    [Authorize(Roles = "user,admin,author")]
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

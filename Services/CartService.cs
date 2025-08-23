using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Services;

public interface ICartService
{
    Task<List<Cart>> GetUserCartAsync(string userId);
    Task<int> GetCartCountAsync(string userId);
    Task<Cart?> AddToCartAsync(string userId, int bookId, int quantity = 1);
    Task<bool> RemoveFromCartAsync(string userId, int bookId);
    Task<bool> UpdateCartItemQuantityAsync(string userId, int bookId, int quantity);
    Task<bool> ClearCartAsync(string userId);
    Task<List<CartItemDTO>> GetCartItemDTOsAsync(string userId);
    Task MigrateSessionCartToUserAsync(List<CartItemDTO> sessionCart, string userId);
}

public class CartService : ICartService
{
    private readonly ApplicationDbContext _context;

    public CartService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<List<Cart>> GetUserCartAsync(string userId)
    {
        return await _context.Carts
            .Include(c => c.Book)
            .Where(c => c.UserId == userId)
            .OrderBy(c => c.CreatedDateTime)
            .ToListAsync();
    }

    public async Task<int> GetCartCountAsync(string userId)
    {
        return await _context.Carts
            .Where(c => c.UserId == userId)
            .SumAsync(c => c.Quantity);
    }

    public async Task<Cart?> AddToCartAsync(string userId, int bookId, int quantity = 1)
    {
        // Check if book exists
        var book = await _context.Books.FindAsync(bookId);
        if (book == null) return null;

        // Check if item already exists in cart
        var existingCartItem = await _context.Carts
            .FirstOrDefaultAsync(c => c.UserId == userId && c.BookId == bookId);

        if (existingCartItem != null)
        {
            // Update existing item
            existingCartItem.Quantity += quantity;
            existingCartItem.UpdatedDateTime = DateTime.Now;
            
            try
            {
                await _context.SaveChangesAsync();
                return existingCartItem;
            }
            catch (DbUpdateException)
            {
                // Handle potential race condition
                _context.Entry(existingCartItem).Reload();
                existingCartItem.Quantity += quantity;
                existingCartItem.UpdatedDateTime = DateTime.Now;
                await _context.SaveChangesAsync();
                return existingCartItem;
            }
        }
        else
        {
            // Create new cart item
            var cartItem = new Cart
            {
                UserId = userId,
                BookId = bookId,
                Quantity = quantity,
                CreatedDateTime = DateTime.Now,
                UpdatedDateTime = DateTime.Now
            };

            try
            {
                _context.Carts.Add(cartItem);
                await _context.SaveChangesAsync();
                return cartItem;
            }
            catch (DbUpdateException)
            {
                // Handle unique constraint violation (race condition)
                // Item was added by another request, so update instead
                var newExistingItem = await _context.Carts
                    .FirstOrDefaultAsync(c => c.UserId == userId && c.BookId == bookId);
                
                if (newExistingItem != null)
                {
                    newExistingItem.Quantity += quantity;
                    newExistingItem.UpdatedDateTime = DateTime.Now;
                    await _context.SaveChangesAsync();
                    return newExistingItem;
                }
                throw; // Re-throw if it's a different error
            }
        }
    }

    public async Task<bool> RemoveFromCartAsync(string userId, int bookId)
    {
        var cartItem = await _context.Carts
            .FirstOrDefaultAsync(c => c.UserId == userId && c.BookId == bookId);

        if (cartItem != null)
        {
            _context.Carts.Remove(cartItem);
            await _context.SaveChangesAsync();
            return true;
        }

        return false;
    }

    public async Task<bool> UpdateCartItemQuantityAsync(string userId, int bookId, int quantity)
    {
        if (quantity <= 0)
        {
            return await RemoveFromCartAsync(userId, bookId);
        }

        var cartItem = await _context.Carts
            .FirstOrDefaultAsync(c => c.UserId == userId && c.BookId == bookId);

        if (cartItem != null)
        {
            cartItem.Quantity = quantity;
            cartItem.UpdatedDateTime = DateTime.Now;
            await _context.SaveChangesAsync();
            return true;
        }

        return false;
    }

    public async Task<bool> ClearCartAsync(string userId)
    {
        var cartItems = await _context.Carts
            .Where(c => c.UserId == userId)
            .ToListAsync();

        if (cartItems.Any())
        {
            _context.Carts.RemoveRange(cartItems);
            await _context.SaveChangesAsync();
            return true;
        }

        return false;
    }

    public async Task<List<CartItemDTO>> GetCartItemDTOsAsync(string userId)
    {
        var cartItems = await _context.Carts
            .Include(c => c.Book)
            .Where(c => c.UserId == userId)
            .Select(c => new CartItemDTO
            {
                BookId = c.BookId,
                Title = c.Book.Title,
                Price = c.Book.Price,
                Quantity = c.Quantity
            })
            .ToListAsync();

        return cartItems;
    }

    public async Task MigrateSessionCartToUserAsync(List<CartItemDTO> sessionCart, string userId)
    {
        if (!sessionCart.Any()) return;

        foreach (var sessionItem in sessionCart)
        {
            await AddToCartAsync(userId, sessionItem.BookId, sessionItem.Quantity);
        }
    }
}

using System.Security.Claims;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Services
{
	public class BookService
	{
		private readonly ApplicationDbContext _db;

		public BookService(ApplicationDbContext db)
		{
			_db = db;
		}

		public async Task<IEnumerable<Book>> GetAllBooks()
		{
			return await _db.Books.Include(b => b.Category).Include(b => b.Author).ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetBooksByCategory(int categoryId)
		{
			return await _db.Books.Include(b => b.Category).Include(b => b.Author).Where(b => b.CategoryId == categoryId).ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetBooksByAuthor(string authorId)
		{
			return await _db.Books.Include(b => b.Category).Include(b => b.Author).Where(b => b.AuthorId == authorId).ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetBooksBySearch(string searchQuery)
		{
			return await _db.Books.Include(b => b.Category).Include(b => b.Author).Where(b => b.Title.Contains(searchQuery) || b.Description.Contains(searchQuery)).ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetFeaturedBooks(int count = 6)
		{
			return await _db.Books
				.Include(b => b.Category)
				.Include(b => b.Author)
				.Where(b => b.IsFeatured)
				.OrderByDescending(b => b.CreatedDateTime)
				.Take(count)
				.ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetLatestBooks(int count = 6)
		{
			return await _db.Books
				.Include(b => b.Category)
				.Include(b => b.Author)
				.OrderByDescending(b => b.CreatedDateTime)
				.Take(count)
				.ToListAsync();
		}

		public async Task<bool> SetBookFeaturedStatus(int bookId, bool isFeatured)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book == null) return false;

			book.IsFeatured = isFeatured;
			book.UpdatedDateTime = DateTime.Now;
			
			await _db.SaveChangesAsync();
			return true;
		}

		public IQueryable<Book> GetBooksQuery()
		{
			return _db.Books.Include(b => b.Category).AsQueryable();
		}

		public async Task<Book?> GetBookById(int id)
		{
			Book? book = await _db.Books.Include(b => b.Category).Include(b => b.Author).FirstOrDefaultAsync(b => b.Id == id);
			return book;
		}

		// TODO: fix: inforcing unique ISBN in the database
		// the problem is that it seems to return true even if the ISBN is not unique
		public async Task<bool> IsISBNUnique(string isbn, int? id = null)
		{
			return !await _db.Books.AnyAsync(b => b.ISBN == isbn && (id == null || b.Id != id));
		}

		public async Task CreateBook(CreateBookDto createBookDto, string authorId)
		{
			Book book = new()
			{
				Title = createBookDto.Title,
				ISBN = createBookDto.ISBN,
				AuthorId = authorId,
				Description = createBookDto.Description,
				Price = createBookDto.Price,
				PublishedDate = createBookDto.PublishedDate,
				CoverImageUrl = createBookDto.CoverImageUrl,
				CategoryId = createBookDto.CategoryId,
				IsFeatured = createBookDto.IsFeatured
			};

			await _db.Books.AddAsync(book);
			await _db.SaveChangesAsync();
		}

		public async Task UpdateBook(int id, UpdateBookDto updateBookDto)
		{
			Book? book = await _db.Books.FindAsync(id);
			if (book != null)
			{
				book.Title = updateBookDto.Title;
				book.ISBN = updateBookDto.ISBN;
				book.Price = updateBookDto.Price;
				book.Description = updateBookDto.Description;
				book.PublishedDate = updateBookDto.PublishedDate;
				book.CoverImageUrl = updateBookDto.CoverImageUrl;
				book.CategoryId = updateBookDto.CategoryId;
				book.IsFeatured = updateBookDto.IsFeatured;
				book.UpdatedDateTime = updateBookDto.UpdatedDateTime;

				_db.Books.Update(book);
				await _db.SaveChangesAsync();
			}
		}

		public async Task DeleteBook(int id)
		{
			var book = await _db.Books.FindAsync(id);
			if (book != null)
			{
				_db.Books.Remove(book);
				await _db.SaveChangesAsync();
			}
		}

	}
}
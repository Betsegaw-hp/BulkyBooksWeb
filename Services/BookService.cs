using BulkyBooksWeb.Data;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models;
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
			return await _db.Books.Include(b => b.Category).ToListAsync();
		}

		public async Task<Book?> GetBookById(int id)
		{
			Book? book = await _db.Books.Include(b => b.Category).FirstOrDefaultAsync(b => b.Id == id);
			return book;
		}

		// TODO: fix: inforcing unique ISBN in the database
		// the problem is that it seems to return true even if the ISBN is not unique
		public async Task<bool> IsISBNUnique(string isbn, int? id = null)
		{
			return !await _db.Books.AnyAsync(b => b.ISBN == isbn && (id == null || b.Id != id));
		}

		public async Task CreateBook(CreateBookDto createBookDto)
		{
			Book book = new()
			{
				Title = createBookDto.Title,
				ISBN = createBookDto.ISBN,
				Author = createBookDto.Author,
				Description = createBookDto.Description,
				Price = createBookDto.Price,
				PublishedDate = createBookDto.PublishedDate,
				// CoverImageUrl = createBookDto.CoverImageUrl,
				CategoryId = createBookDto.CategoryId
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
				book.Author = updateBookDto.Author;
				book.Price = updateBookDto.Price;
				book.Description = updateBookDto.Description;
				book.PublishedDate = updateBookDto.PublishedDate;
				// book.CoverImageUrl = updateBookDto.CoverImageUrl;
				book.CategoryId = updateBookDto.CategoryId;
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
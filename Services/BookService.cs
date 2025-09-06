using System.Security.Claims;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BulkyBooksWeb.Services
{
	public class BookService
	{
		private readonly ApplicationDbContext _db;
		private readonly IBlobStorageService _blobStorageService;
		private readonly AzureConfiguration _azureConfig;

		/// <summary>
		/// Initializes a new instance of the <see cref="BookService"/> class.
		/// </summary>
		/// <param name="db">The application's database context.</param>
		/// <param name="blobStorageService">Azure Blob Storage service for file uploads.</param>
		/// <param name="azureConfig">Azure configuration settings.</param>
		public BookService(
			ApplicationDbContext db, 
			IBlobStorageService blobStorageService, 
			IOptions<AzureConfiguration> azureConfig)
		{
			_db = db;
			_blobStorageService = blobStorageService;
			_azureConfig = azureConfig.Value;
		}

		public async Task<IEnumerable<Book>> GetAllBooks()
		{
			return await _db.Books.Include(b => b.Category).Include(b => b.Author).ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetAllPublishedBooks()
		{
			return await _db.Books
				.Include(b => b.Category)
				.Include(b => b.Author)
				.Where(b => b.Status == BookStatus.Published)
				.ToListAsync();
		}

		public async Task<IEnumerable<Book>> GetBooksByCategory(int categoryId)
		{
			return await _db.Books
				.Include(b => b.Category)
				.Include(b => b.Author)
				.Where(b => b.CategoryId == categoryId && b.Status == BookStatus.Published)
				.ToListAsync();
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
			return _db.Books.Include(b => b.Category).Where(b => b.Status == BookStatus.Published).AsQueryable();
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
		string? pdfPath = null;
		if (createBookDto.PdfFile != null)
		{
			pdfPath = await SavePdfFile(createBookDto.PdfFile);
		}

		string? coverImagePath = null;
		if (createBookDto.CoverImageFile != null)
		{
			coverImagePath = await SaveCoverImageFile(createBookDto.CoverImageFile);
		}

		Book book = new()
		{
			Title = createBookDto.Title,
			ISBN = createBookDto.ISBN,
			AuthorId = authorId,
			Description = createBookDto.Description,
			Price = createBookDto.Price,
			PublishedDate = createBookDto.PublishedDate,
			CoverImagePath = coverImagePath,
			CategoryId = createBookDto.CategoryId,
			IsFeatured = createBookDto.IsFeatured,
			PdfFilePath = pdfPath,
			Status = BookStatus.Draft // Authors can only create drafts initially
		};

		await _db.Books.AddAsync(book);
		await _db.SaveChangesAsync();
	}

	private async Task<string> SavePdfFile(IFormFile pdfFile)
	{
		try
		{
			var fileName = $"{Guid.NewGuid()}{Path.GetExtension(pdfFile.FileName)}";
			var fileUrl = await _blobStorageService.UploadFileAsync(
				pdfFile, 
				_azureConfig.BlobStorage.Containers.BookPdfs,
				fileName);
			return fileUrl;
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException($"Failed to upload PDF file: {ex.Message}", ex);
		}
	}

	private async Task<string> SaveCoverImageFile(IFormFile imageFile)
	{
		try
		{
			var fileName = $"{Guid.NewGuid()}{Path.GetExtension(imageFile.FileName)}";
			var fileUrl = await _blobStorageService.UploadFileAsync(
				imageFile, 
				_azureConfig.BlobStorage.Containers.BookCovers,
				fileName);
			return fileUrl;
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException($"Failed to upload cover image: {ex.Message}", ex);
		}
	}

	public async Task UpdateBook(int id, UpdateBookDto updateBookDto, IFormFile? pdfFile = null, IFormFile? coverImageFile = null)
	{
		Book? book = await _db.Books.FindAsync(id);
		if (book != null)
		{
			book.Title = updateBookDto.Title;
			book.ISBN = updateBookDto.ISBN;
			book.Price = updateBookDto.Price;
			book.Description = updateBookDto.Description;
			book.PublishedDate = updateBookDto.PublishedDate;
			book.CategoryId = updateBookDto.CategoryId;
			book.IsFeatured = updateBookDto.IsFeatured;
			book.UpdatedDateTime = updateBookDto.UpdatedDateTime;

			// Handle PDF file update
			if (pdfFile != null)
			{
				string pdfPath = await SavePdfFile(pdfFile);
				book.PdfFilePath = pdfPath;
			}

			// Handle cover image file update
			if (coverImageFile != null)
			{
				string coverImagePath = await SaveCoverImageFile(coverImageFile);
				book.CoverImagePath = coverImagePath;
			}

			_db.Books.Update(book);
			await _db.SaveChangesAsync();
		}
	}
		public async Task DeleteBook(int id)
		{
			var book = await _db.Books.FindAsync(id);
			if (book != null)
			{
				// Delete associated files from Azure Blob Storage
				try
				{
					if (!string.IsNullOrEmpty(book.CoverImagePath))
					{
						await _blobStorageService.DeleteFileAsync(
							book.CoverImagePath, 
							_azureConfig.BlobStorage.Containers.BookCovers);
					}

					if (!string.IsNullOrEmpty(book.PdfFilePath))
					{
						await _blobStorageService.DeleteFileAsync(
							book.PdfFilePath, 
							_azureConfig.BlobStorage.Containers.BookPdfs);
					}
				}
				catch (Exception ex)
				{
					// Log the error but continue with book deletion
					// Consider using ILogger here
					Console.WriteLine($"Warning: Failed to delete files for book {id}: {ex.Message}");
				}

				_db.Books.Remove(book);
				await _db.SaveChangesAsync();
			}
		}

		// Book review workflow methods
		public async Task<IEnumerable<Book>> GetBooksByStatus(BookStatus status)
		{
			return await _db.Books
				.Include(b => b.Category)
				.Include(b => b.Author)
				.Where(b => b.Status == status)
				.ToListAsync();
		}

		public async Task SubmitBookForReview(int bookId)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book != null && (book.Status == BookStatus.Draft || book.Status == BookStatus.Rejected))
			{
				book.Status = BookStatus.UnderReview;
				book.SubmittedAt = DateTime.Now;
				book.UpdatedDateTime = DateTime.Now;
				book.ReviewSubmissionCount++;
				book.HasSignificantChanges = false; // Reset flag after submission
				book.AdminReviewComments = null; // Clear previous comments
				book.ReviewedAt = null; // Clear previous review date
				book.ReviewedBy = null; // Clear previous reviewer
				await _db.SaveChangesAsync();
			}
		}

		public async Task ResubmitBookForReview(int bookId)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book != null && (book.Status == BookStatus.Approved || book.Status == BookStatus.Published || book.Status == BookStatus.Rejected))
			{
				book.Status = BookStatus.ResubmittedForReview;
				book.SubmittedAt = DateTime.Now;
				book.UpdatedDateTime = DateTime.Now;
				book.ReviewSubmissionCount++;
				book.HasSignificantChanges = false; // Reset flag after resubmission
				await _db.SaveChangesAsync();
			}
		}

		public async Task ApproveBook(int bookId, string reviewerId, string? comments = null)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book != null && (book.Status == BookStatus.UnderReview || book.Status == BookStatus.ResubmittedForReview))
			{
				book.Status = BookStatus.Approved;
				book.ReviewedAt = DateTime.UtcNow;
				book.ReviewedBy = reviewerId;
				book.AdminReviewComments = comments;
				book.UpdatedDateTime = DateTime.Now;
				await _db.SaveChangesAsync();
			}
		}

		public async Task RejectBook(int bookId, string reviewerId, string? comments = null)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book != null && (book.Status == BookStatus.UnderReview || book.Status == BookStatus.ResubmittedForReview))
			{
				book.Status = BookStatus.Rejected;
				book.ReviewedAt = DateTime.UtcNow;
				book.ReviewedBy = reviewerId;
				book.AdminReviewComments = comments;
				book.UpdatedDateTime = DateTime.Now;
				await _db.SaveChangesAsync();
			}
		}

		public async Task PublishBook(int bookId)
		{
			var book = await _db.Books.FindAsync(bookId);
			if (book != null && book.Status == BookStatus.Approved)
			{
				book.Status = BookStatus.Published;
				book.UpdatedDateTime = DateTime.Now;
				await _db.SaveChangesAsync();
			}
		}

		public async Task<bool> CheckAndMarkSignificantChanges(int bookId, UpdateBookDto updatedBook, bool pdfChanged = false, bool coverImageChanged = false)
		{
			var existingBook = await _db.Books.FindAsync(bookId);
			if (existingBook == null) return false;

		// Define what constitutes significant changes
		bool hasSignificantChanges = 
			existingBook.Title != updatedBook.Title ||
			existingBook.Description != updatedBook.Description ||
			existingBook.ISBN != updatedBook.ISBN ||
			existingBook.CategoryId != updatedBook.CategoryId ||
			pdfChanged || // PDF file change is always significant
			coverImageChanged; // Cover image change is also significant

		if (hasSignificantChanges && (existingBook.Status == BookStatus.Approved || existingBook.Status == BookStatus.Published))
		{
			existingBook.HasSignificantChanges = true;
			existingBook.Status = BookStatus.ResubmittedForReview;
			existingBook.SubmittedAt = DateTime.Now;
			existingBook.ReviewSubmissionCount++;
			await _db.SaveChangesAsync();
			return true;
		}
		else if (hasSignificantChanges)
		{
			existingBook.HasSignificantChanges = true;
			await _db.SaveChangesAsync();
		}

		return hasSignificantChanges;
		}

	}
}
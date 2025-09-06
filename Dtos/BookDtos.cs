using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Dtos
{
	public abstract class BaseBookDto
	{
		[Required]
		[StringLength(50)]
		public string Title { get; set; } = string.Empty;

		[MaxLength(500)]
		public string Description { get; set; } = string.Empty;

		[Required]
		[RegularExpression(@"^(?:\d{3}-)?\d{1,5}-\d{1,7}-\d{1,7}-[\dX]$",
			ErrorMessage = "Invalid ISBN format (e.g., 123-45-67890-12-3 or 1234567890123)")]
		public virtual string ISBN { get; set; } = string.Empty;

		[Url(ErrorMessage = "Invalid URL format.")]
		public string CoverImageUrl { get; set; } = string.Empty;

		public DateTime PublishedDate { get; set; }

		[ForeignKey("Category")]
		[Required(ErrorMessage = "Please select a category.")]
		public int CategoryId { get; set; }

		[Column(TypeName = "decimal(18, 2)")]
		[Range(0.01, 1000.00)]
		public decimal Price { get; set; }

		[Display(Name = "Featured Book")]
		public bool IsFeatured { get; set; } = false;
	}

	public class BookDto : BaseBookDto
	{
		[Key]
		public int Id { get; set; }

		public DateTime CreatedDateTime { get; set; }
		public DateTime UpdatedDateTime { get; set; }

		public virtual Category? Category { get; set; }
	}

	public class CreateBookDto : BaseBookDto
	{
		[Remote("IsISBNUnique", "Book", ErrorMessage = "ISBN already exists.")]
		public override string ISBN { get; set; } = string.Empty;

		[Display(Name = "PDF File")]
		public IFormFile? PdfFile { get; set; }
	}

	public class UpdateBookDto : BaseBookDto
	{
		[Key]
		public int Id { get; set; }

		[Remote("IsISBNUnique", "Book", AdditionalFields = nameof(Id), ErrorMessage = "ISBN already exists.")]
		public override string ISBN { get; set; } = string.Empty;

		public DateTime UpdatedDateTime { get; set; } = DateTime.Now;
	}
}

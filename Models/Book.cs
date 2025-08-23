using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Models
{
	public class Book
	{
		[Key]
		public int Id { get; set; }

		[ForeignKey("Category")]
		public int CategoryId { get; set; }

		[ForeignKey("Author")]
		public string AuthorId { get; set; } = string.Empty;

		[Required]
		[StringLength(100)]
		public string Title { get; set; } = string.Empty;

		[MaxLength(500)]
		public string Description { get; set; } = string.Empty;

		[Required]
		[Remote("IsISBNUnique", "Book", ErrorMessage = "ISBN already exists.")]
		[RegularExpression(@"^(?:\d{3}-)?\d{1,5}-\d{1,7}-\d{1,7}-[\dX]$",
			ErrorMessage = "Invalid ISBN format (e.g., 123-45-67890-12-3 or 1234567890123)")]
		public string ISBN { get; set; } = string.Empty;

		[Column(TypeName = "decimal(18, 2)")]
		[Range(0.01, 1000000.00)]
		public decimal Price { get; set; }

		[DataType(DataType.Date)]
		public DateTime PublishedDate { get; set; }

		public string CoverImageUrl { get; set; } = string.Empty;

		[Display(Name = "Featured Book")]
		public bool IsFeatured { get; set; } = false;

		// Navigation property
		public virtual Category Category { get; set; } = null!;
		public virtual ApplicationUser Author { get; set; } = null!;

		public DateTime CreatedDateTime { get; set; } = DateTime.Now;
		public DateTime UpdatedDateTime { get; set; } = DateTime.Now;
	}
}
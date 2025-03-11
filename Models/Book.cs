using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BulkyBooksWeb.Models
{
	public class Book
	{
		[Key]
		public int Id { get; set; }

		[ForeignKey("Category")]
		public int CategoryId { get; set; }

		[Required]
		[StringLength(100)]
		public string Title { get; set; } = string.Empty;

		[Required]
		[StringLength(50)]
		public string Author { get; set; } = string.Empty;

		[Required]
		[RegularExpression(@"^(?:\d{3}-)?\d{1,5}-\d{1,7}-\d{1,7}-[\dX]$",
			ErrorMessage = "Invalid ISBN format (e.g., 123-45-67890-12-3 or 1234567890123)")]
		public string ISBN { get; set; } = string.Empty;

		[Column(TypeName = "decimal(18, 2)")]
		[Range(0.01, 1000.00)]
		public decimal Price { get; set; }

		[DataType(DataType.Date)]
		public DateTime PublishedDate { get; set; }

		// Navigation property
		public virtual Category? Category { get; set; }
	}
}
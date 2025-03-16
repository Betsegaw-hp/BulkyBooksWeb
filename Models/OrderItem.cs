using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BulkyBooksWeb.Models
{
	public class OrderItem
	{
		[Key]
		public int Id { get; set; }

		[ForeignKey("Order")]
		[Required]
		public int OrderId { get; set; }

		[ForeignKey("Book")]
		[Required]
		public int BookId { get; set; }
		public string BookTitle { get; set; } = string.Empty;

		[Column(TypeName = "decimal(18, 2)")]
		[Range(0.01, 1000000.00)]
		public decimal Price { get; set; }

		[Required]
		[Range(1, 1000, ErrorMessage = "Quantity must be between 1 and 1000.")]
		public int Quantity { get; set; }

		// Navigation properties
		public virtual Order Order { get; set; } = null!;
	}
}
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BulkyBooksWeb.Models
{

	public enum OrderStatus
	{
		Pending,
		Completed,
		Refunded,
		Cancelled,
		Failed
	}
	public class Order
	{
		[Key]
		public int Id { get; set; }

		[ForeignKey("User")]
		[Required]
		public int UserId { get; set; }

		public DateTime OrderDate { get; set; } = DateTime.UtcNow;

		[Column(TypeName = "decimal(18, 2)")]
		[Range(0.01, 1000000.00)]
		public decimal OrderTotal { get; set; }
		public OrderStatus Status { get; set; } = OrderStatus.Pending;
		public string TransactionReference { get; set; } = string.Empty;
		public DateTime? PaymentDate { get; set; }

		[MaxLength(500)]
		[MinLength(10)]
		[DataType(DataType.MultilineText)]
		public string? Note { get; set; } = string.Empty;

		// Navigation properties
		public virtual List<OrderItem> OrderItems { get; set; } = new();
		public virtual User User { get; set; } = null!;
	}
}
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Dtos
{
	public class OrderConfirmationDto
	{
		public int Id { get; set; }
		public int UserId { get; set; }
		public string OwnerEmail { get; set; } = string.Empty;
		public DateTime OrderDate { get; set; }
		public decimal OrderTotal { get; set; }
		public OrderStatus Status { get; set; }
		public string TransactionReference { get; set; } = string.Empty;
		public List<OrderItemDto> OrderItems { get; set; } = [];

	}

}
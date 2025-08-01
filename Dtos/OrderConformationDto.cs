using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Dtos
{
	public class OrderConfirmationDto
	{
		public int Id { get; set; }
		public string UserId { get; set; } = string.Empty;
		public string OwnerEmail { get; set; } = string.Empty;
		public DateTime OrderDate { get; set; }
		public decimal OrderTotal { get; set; }
		public OrderStatus Status { get; set; }
		public string TransactionReference { get; set; } = string.Empty;
		public List<OrderItemDto> OrderItems { get; set; } = [];

	}

	public class TrxResponseDto
	{
		public string trx_ref { get; set; } = string.Empty;
		public string ref_id { get; set; } = string.Empty;
		public string status { get; set; } = string.Empty;
	}
}
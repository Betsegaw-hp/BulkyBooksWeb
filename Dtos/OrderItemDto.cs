namespace BulkyBooksWeb.Dtos
{
	public class OrderItemDto
	{
		public int BookId { get; set; }
		public int BookAuthorId { get; set; }
		public string BookTitle { get; set; } = string.Empty;
		public decimal Price { get; set; }
		public int Quantity { get; set; }

		// public string ImageUrl { get; set; } = string.Empty;
		public string Author { get; set; } = string.Empty;
	}
}
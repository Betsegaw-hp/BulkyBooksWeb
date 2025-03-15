using System.ComponentModel.DataAnnotations;

namespace BulkyBooksWeb.Models.ViewModels
{
	public class CheckoutViewModel
	{
		public List<CartItemDTO> CartItems { get; set; } = null!;
		public decimal Subtotal { get; set; }
		public decimal TaxAmount { get; set; }
		public decimal OrderTotal { get; set; }

		[Required]
		[EmailAddress]
		public string Email { get; set; } = string.Empty;

		[Required]
		[Phone]
		[RegularExpression(@"^(09|07)\d{8}$", ErrorMessage = "Invalid phone number format.")]
		public string PhoneNumber { get; set; } = string.Empty;

		[Required] public string FirstName { get; set; } = string.Empty;
		[Required] public string LastName { get; set; } = string.Empty;

		public string? Currency { get; set; } = "ETB";

		public string CallbackURL { get; set; } = "https://mysite.com/callback";
		public string ReturnURL { get; set; } = "https://mysite.com/success";
	}

	public class CartItemDTO
	{
		public int BookId { get; set; }
		public string Title { get; set; } = string.Empty;
		public decimal Price { get; set; }
		public int Quantity { get; set; }
	}
}
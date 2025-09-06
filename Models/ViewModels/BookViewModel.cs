using BulkyBooksWeb.Dtos;
namespace BulkyBooksWeb.Models.ViewModels
{
	public class BookCreateViewModel
	{
		public CreateBookDto CreateBookDto { get; set; } = null!;  // For form data binding
		public IEnumerable<Category> Categories { get; set; } = null!;  // For dropdown/list
	}
	public class BookUpdateViewModel
	{
		public UpdateBookDto UpdateBookDto { get; set; } = null!;  // For form data binding
		public IEnumerable<Category> Categories { get; set; } = null!;  // For dropdown/list
		public string? CurrentPdfFilePath { get; set; }  // Current PDF file path for display
	}

}
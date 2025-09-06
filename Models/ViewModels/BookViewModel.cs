using BulkyBooksWeb.Dtos;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace BulkyBooksWeb.Models.ViewModels
{
	public class BookCreateViewModel
	{
		public CreateBookDto CreateBookDto { get; set; } = null!;  // For form data binding
		
		[ValidateNever]
		public IEnumerable<Category> Categories { get; set; } = null!;  // For dropdown/list - not submitted
	}
	public class BookUpdateViewModel
	{
		public UpdateBookDto UpdateBookDto { get; set; } = null!;  // For form data binding
		
		[ValidateNever]
		public IEnumerable<Category> Categories { get; set; } = null!;  // For dropdown/list - not submitted
		public string? CurrentPdfFilePath { get; set; }  // Current PDF file path for display
		public string? CurrentCoverImagePath { get; set; }  // Current cover image path for display
	}

}
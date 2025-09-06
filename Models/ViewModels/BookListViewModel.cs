
namespace BulkyBooksWeb.Models.ViewModels
{
	public class BookListViewModel
	{
		public IEnumerable<Book> Books { get; set; } = null!;
		public IEnumerable<Book> FeaturedBooks { get; set; } = null!;
		public IEnumerable<CategoryViewModel> FeaturedCategories { get; set; } = null!;
		public IEnumerable<CategoryViewModel> AllCategories { get; set; } = null!;
		public FilterViewModel CurrentFilter { get; set; } = null!;
		public int CurrentPage { get; set; }
		public int TotalPages { get; set; }
		public int TotalBooks { get; set; }

		public bool HasActiveFilters
		{
			get
			{
				return !string.IsNullOrEmpty(CurrentFilter.SearchQuery) ||
					   (CurrentFilter.CategoryIds != null && CurrentFilter.CategoryIds.Any()) ||
					   CurrentFilter.MinPrice.HasValue ||
					   CurrentFilter.MaxPrice.HasValue ||
					   CurrentFilter.ShowFeaturedOnly;
			}
		}
	}

	public class FilterViewModel
	{
		public string SearchQuery { get; set; } = string.Empty;
		public IEnumerable<int> CategoryIds { get; set; } = null!;
		public decimal? MinPrice { get; set; }
		public decimal? MaxPrice { get; set; }
		public string SortOption { get; set; } = "newest";
		public bool ShowFeaturedOnly { get; set; } = false;
	}

	public class CategoryViewModel
	{
		public int Id { get; set; }
		public string Name { get; set; } = string.Empty;
		public int BookCount { get; set; }
		public int DisplayOrder { get; set; }
	}
}
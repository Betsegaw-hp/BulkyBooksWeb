using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Dtos
{
	public class CategoryDto
	{
		public int Id { get; set; }
		public string Name { get; set; } = string.Empty;
		public int DisplayOrder { get; set; }
		public DateTime CreatedDateTime { get; set; }
		public DateTime UpdatedDateTime { get; set; }

		public virtual ICollection<Book>? Books { get; set; }

	}

	public class CreateCategoryDto
	{
		public string Name { get; set; } = string.Empty;
		public int DisplayOrder { get; set; }
	}
}
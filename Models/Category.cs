using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Models
{
	public class Category
	{
		[Key]
		public int Id { get; set; }

		[Required]
		[StringLength(100)]
		[Remote("IsCategoryNameUnique", "Category", ErrorMessage = "Category name already exists.")]
		public string Name { get; set; } = string.Empty;

		[Range(1, 100, ErrorMessage = "Display order must be between 1 and 100.")]
		public int DisplayOrder { get; set; }
		public DateTime CreatedDateTime { get; set; } = DateTime.Now;
		public DateTime UpdatedDateTime { get; set; } = DateTime.Now;
	}
}
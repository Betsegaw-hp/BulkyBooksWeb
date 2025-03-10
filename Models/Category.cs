using System.ComponentModel.DataAnnotations;

namespace BulkyBooksWeb.Models
{
	public class Category
	{
		[Key]
		public int Id { get; set; }
		[Required]
		public string Name { get; set; } = string.Empty;
		public int DisplayOrder { get; set; }
		public DateTime CreatedDateTime { get; set; } = DateTime.Now;
		public DateTime UpdatedDateTime { get; set; } = DateTime.Now;
	}
}
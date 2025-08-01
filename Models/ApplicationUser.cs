using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace BulkyBooksWeb.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [MaxLength(50)]
        public string LastName { get; set; } = string.Empty;

        public string AvatarUrl { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginAt { get; set; }

        [Required]
        [MaxLength(100)]
        public string FullName => $"{FirstName} {LastName}".Trim();

        // Navigation properties
        public virtual ICollection<Book> Books { get; set; } = new List<Book>();
        public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
    }
}

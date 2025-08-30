using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using BulkyBooksWeb.Models;

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

        // KYC fields
        public KycStatus KycStatus { get; set; } = KycStatus.Pending;
        public string? IdProofPath { get; set; }
        public string? AddressProofPath { get; set; }
        public string? AuthorPhotoPath { get; set; }
        public DateTime? KycVerifiedAt { get; set; }
        public string? KycAdminNotes { get; set; }

        // Navigation properties
        public virtual ICollection<Book> Books { get; set; } = new List<Book>();
        public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
    }
}

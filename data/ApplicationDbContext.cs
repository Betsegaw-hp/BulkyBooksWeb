using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace BulkyBooksWeb.Data
{
	public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
	{
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
		{ }

		public DbSet<Category> Categories { get; set; }
		public DbSet<Book> Books { get; set; }
		public DbSet<User> LegacyUsers { get; set; }
		public DbSet<Order> Orders { get; set; }
		public DbSet<OrderItem> OrderItems { get; set; }
		public DbSet<Cart> Carts { get; set; }

		// public DbSet<CoverType> CoverTypes { get; set; } = default!;
		// public DbSet<Product> Products { get; set; } = default!;
		// public DbSet<ShoppingCart> ShoppingCarts { get; set; } = default!;
		// public DbSet<OrderHeader> OrderHeaders { get; set; } = default!;
		// public DbSet<OrderDetails> OrderDetails { get; set; } = default!;

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			base.OnModelCreating(modelBuilder);

			// Rename Identity tables to avoid conflicts
			modelBuilder.Entity<ApplicationUser>().ToTable("AspNetUsers");
			modelBuilder.Entity<IdentityRole>().ToTable("AspNetRoles");
			modelBuilder.Entity<IdentityUserRole<string>>().ToTable("AspNetUserRoles");
			modelBuilder.Entity<IdentityUserClaim<string>>().ToTable("AspNetUserClaims");
			modelBuilder.Entity<IdentityUserLogin<string>>().ToTable("AspNetUserLogins");
			modelBuilder.Entity<IdentityRoleClaim<string>>().ToTable("AspNetRoleClaims");
			modelBuilder.Entity<IdentityUserToken<string>>().ToTable("AspNetUserTokens");

			// Rename old Users table for migration purposes
			modelBuilder.Entity<User>().ToTable("LegacyUsers");

			// Existing constraints
			modelBuilder.Entity<Book>()
				.HasIndex(b => b.ISBN)
				.IsUnique();

			modelBuilder.Entity<User>()
				.HasIndex(u => u.Username)
				.IsUnique();

			// Cart entity configuration
			modelBuilder.Entity<Cart>()
				.HasOne(c => c.User)
				.WithMany()
				.HasForeignKey(c => c.UserId)
				.OnDelete(DeleteBehavior.Cascade);

			modelBuilder.Entity<Cart>()
				.HasOne(c => c.Book)
				.WithMany()
				.HasForeignKey(c => c.BookId)
				.OnDelete(DeleteBehavior.NoAction); // Prevent cascade delete conflicts

			// Unique constraint to prevent duplicate cart items
			modelBuilder.Entity<Cart>()
				.HasIndex(c => new { c.UserId, c.BookId })
				.IsUnique();
		}


	}
}
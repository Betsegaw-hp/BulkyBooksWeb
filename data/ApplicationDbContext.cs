using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Data
{
	public class ApplicationDbContext : DbContext
	{
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
		{ }

		public DbSet<Category> Categories { get; set; }
		public DbSet<Book> Books { get; set; }
		public DbSet<User> Users { get; set; }
		// public DbSet<Order> Orders { get; set; } 
		// public DbSet<OrderItem> OrderItems { get; set; }

		// public DbSet<CoverType> CoverTypes { get; set; } = default!;
		// public DbSet<Product> Products { get; set; } = default!;
		// public DbSet<ShoppingCart> ShoppingCarts { get; set; } = default!;
		// public DbSet<OrderHeader> OrderHeaders { get; set; } = default!;
		// public DbSet<OrderDetails> OrderDetails { get; set; } = default!;

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.Entity<Book>()
				.HasIndex(b => b.ISBN)
				.IsUnique();

			modelBuilder.Entity<User>()
				.HasIndex(u => u.Username)
				.IsUnique();
		}


	}
}
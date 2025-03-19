using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Connections;

namespace BulkyBooksWeb.Data
{
	public class ApplicationDbContext : DbContext
	{
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
		{ }

		public DbSet<Category> Categories { get; set; }
		public DbSet<Book> Books { get; set; }
		public DbSet<User> Users { get; set; }
		public DbSet<Order> Orders { get; set; }
		public DbSet<OrderItem> OrderItems { get; set; }

		// public DbSet<CoverType> CoverTypes { get; set; } = default!;
		// public DbSet<Product> Products { get; set; } = default!;
		// public DbSet<ShoppingCart> ShoppingCarts { get; set; } = default!;
		// public DbSet<OrderHeader> OrderHeaders { get; set; } = default!;
		// public DbSet<OrderDetails> OrderDetails { get; set; } = default!;
		protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
		{
			optionsBuilder
				.UseLazyLoadingProxies() // Enable lazy loading
				.UseSqlServer("Server=DESKTOP-CQ5L6HL\\SQLEXPRESS;Database=BulkyBooks;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true");
		}

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
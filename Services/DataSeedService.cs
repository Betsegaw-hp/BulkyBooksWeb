using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Data;

namespace BulkyBooksWeb.Services
{
    public class DataSeedService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public DataSeedService(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task SeedAsync()
        {
            // Ensure database is created
            await _context.Database.EnsureCreatedAsync();

            // Create roles
            await CreateRolesAsync();

            // Create admin user
            await CreateAdminUserAsync();

            // Create sample categories
            await CreateCategoriesAsync();

            // Create sample users and books
            await CreateSampleDataAsync();

            await _context.SaveChangesAsync();
        }

        private async Task CreateRolesAsync()
        {
            string[] roles = { "Admin", "Author", "User" };

            foreach (string role in roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    await _roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }

        private async Task CreateAdminUserAsync()
        {
            var adminEmail = "admin@bulkybooks.com";
            var adminUser = await _userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = "admin",
                    Email = adminEmail,
                    FirstName = "System",
                    LastName = "Administrator",
                    AvatarUrl = "/images/default-avatar.png",
                    EmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(adminUser, "Admin123!");
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(adminUser, "Admin");
                }
            }
        }

        private async Task CreateCategoriesAsync()
        {
            if (!await _context.Categories.AnyAsync())
            {
                var categories = new List<Category>
                {
                    new Category { Name = "Fiction", DisplayOrder = 1, CreatedDateTime = DateTime.Now, UpdatedDateTime = DateTime.Now },
                    new Category { Name = "Non-Fiction", DisplayOrder = 2, CreatedDateTime = DateTime.Now, UpdatedDateTime = DateTime.Now },
                    new Category { Name = "Science", DisplayOrder = 3, CreatedDateTime = DateTime.Now, UpdatedDateTime = DateTime.Now },
                    new Category { Name = "Technology", DisplayOrder = 4, CreatedDateTime = DateTime.Now, UpdatedDateTime = DateTime.Now },
                    new Category { Name = "Biography", DisplayOrder = 5, CreatedDateTime = DateTime.Now, UpdatedDateTime = DateTime.Now }
                };

                _context.Categories.AddRange(categories);
                await _context.SaveChangesAsync();
            }
        }

        private async Task CreateSampleDataAsync()
        {
            // Create sample author user
            var authorEmail = "author@bulkybooks.com";
            var authorUser = await _userManager.FindByEmailAsync(authorEmail);

            if (authorUser == null)
            {
                authorUser = new ApplicationUser
                {
                    UserName = "author1",
                    Email = authorEmail,
                    FirstName = "John",
                    LastName = "Author",
                    AvatarUrl = "/images/default-avatar.png",
                    EmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(authorUser, "Author123!");
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(authorUser, "Author");
                }
            }

            // Create sample books
            if (!await _context.Books.AnyAsync() && authorUser != null)
            {
                var fictionCategory = await _context.Categories.FirstOrDefaultAsync(c => c.Name == "Fiction");
                var techCategory = await _context.Categories.FirstOrDefaultAsync(c => c.Name == "Technology");

                if (fictionCategory != null && techCategory != null)
                {
                    var books = new List<Book>
                    {
                        new Book
                        {
                            Title = "The Great Adventure",
                            Description = "An exciting fiction novel about adventure and discovery.",
                            ISBN = "978-1234567890",
                            Price = 19.99m,
                            PublishedDate = new DateTime(2023, 1, 15),
                            CoverImagePath = "/images/book-placeholder.jpg",
                            CategoryId = fictionCategory.Id,
                            AuthorId = authorUser.Id,
                            CreatedDateTime = DateTime.Now,
                            UpdatedDateTime = DateTime.Now
                        },
                        new Book
                        {
                            Title = "Modern Web Development",
                            Description = "A comprehensive guide to building modern web applications.",
                            ISBN = "978-0987654321",
                            Price = 39.99m,
                            PublishedDate = new DateTime(2023, 6, 10),
                            CoverImagePath = "/images/book-placeholder.jpg",
                            CategoryId = techCategory.Id,
                            AuthorId = authorUser.Id,
                            CreatedDateTime = DateTime.Now,
                            UpdatedDateTime = DateTime.Now
                        }
                    };

                    _context.Books.AddRange(books);
                    await _context.SaveChangesAsync();
                }
            }
        }
    }
}

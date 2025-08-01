using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Services
{
    public class UserMigrationService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<UserMigrationService> _logger;
        
        public UserMigrationService(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<UserMigrationService> logger)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }
        
        public async Task MigrateExistingUsers()
        {
            try
            {
                _logger.LogInformation("Starting user migration...");
                
                // Create roles if they don't exist
                string[] roles = { "Admin", "Author", "User" };
                foreach (var roleName in roles)
                {
                    if (!await _roleManager.RoleExistsAsync(roleName))
                    {
                        _logger.LogInformation($"Creating role: {roleName}");
                        await _roleManager.CreateAsync(new IdentityRole(roleName));
                    }
                }
                
                // Get legacy users
                var legacyUsers = await _context.LegacyUsers.ToListAsync();
                _logger.LogInformation($"Found {legacyUsers.Count} legacy users to migrate");
                
                foreach (var oldUser in legacyUsers)
                {
                    var existingUser = await _userManager.FindByNameAsync(oldUser.Username);
                    if (existingUser == null)
                    {
                        _logger.LogInformation($"Migrating user: {oldUser.Username}");
                        
                        var newUser = new ApplicationUser
                        {
                            UserName = oldUser.Username,
                            Email = oldUser.Email,
                            FullName = oldUser.FullName,
                            AvatarUrl = oldUser.AvatarUrl,
                            CreatedAt = oldUser.CreatedAt,
                            UpdatedAt = oldUser.UpdatedAt,
                            EmailConfirmed = true
                        };
                        
                        // Create user with temporary password
                        var result = await _userManager.CreateAsync(newUser, "TempPassword123!");
                        if (result.Succeeded)
                        {
                            // Add to role
                            var role = oldUser.Role.ToString();
                            await _userManager.AddToRoleAsync(newUser, role);
                            
                            // Store the old password hash for manual migration if needed
                            _logger.LogInformation($"User {oldUser.Username} migrated successfully. Role: {role}");
                        }
                        else
                        {
                            _logger.LogError($"Failed to migrate user {oldUser.Username}: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                        }
                    }
                    else
                    {
                        _logger.LogInformation($"User {oldUser.Username} already exists in Identity");
                    }
                }
                
                _logger.LogInformation("User migration completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user migration");
                throw;
            }
        }
        
        public async Task<Dictionary<int, string>> GetUserIdMapping()
        {
            var mapping = new Dictionary<int, string>();
            var legacyUsers = await _context.LegacyUsers.ToListAsync();
            
            foreach (var legacyUser in legacyUsers)
            {
                var identityUser = await _userManager.FindByNameAsync(legacyUser.Username);
                if (identityUser != null)
                {
                    mapping[legacyUser.Id] = identityUser.Id;
                }
            }
            
            return mapping;
        }
    }
}

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using BulkyBooksWeb.Data;

namespace BulkyBooksWeb.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UserManagementController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<UserManagementController> _logger;

        public UserManagementController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext context,
            ILogger<UserManagementController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
        }

        // GET: UserManagement
        public async Task<IActionResult> Index(string searchTerm = "", string roleFilter = "", int page = 1, int pageSize = 10)
        {
            var query = _userManager.Users.AsQueryable();

            // Apply search filter
            if (!string.IsNullOrEmpty(searchTerm))
            {
                query = query.Where(u => u.UserName!.Contains(searchTerm) || 
                                       u.Email!.Contains(searchTerm) || 
                                       u.FullName.Contains(searchTerm));
            }

            var totalUsers = await query.CountAsync();
            var users = await query
                .OrderBy(u => u.UserName)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var userItems = new List<UserManagementItem>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                
                // Apply role filter
                if (!string.IsNullOrEmpty(roleFilter) && !roles.Contains(roleFilter))
                    continue;

                userItems.Add(new UserManagementItem
                {
                    Id = user.Id,
                    UserName = user.UserName ?? "",
                    Email = user.Email ?? "",
                    FullName = user.FullName,
                    AvatarUrl = user.AvatarUrl ?? "",
                    Roles = roles.ToList(),
                    EmailConfirmed = user.EmailConfirmed,
                    LockoutEnabled = user.LockoutEnabled,
                    LockoutEnd = user.LockoutEnd,
                    CreatedAt = user.CreatedAt,
                    UpdatedAt = user.UpdatedAt,
                    AccessFailedCount = user.AccessFailedCount,
                    TwoFactorEnabled = user.TwoFactorEnabled
                });
            }

            var viewModel = new UserManagementViewModel
            {
                Users = userItems,
                SearchTerm = searchTerm,
                RoleFilter = roleFilter,
                CurrentPage = page,
                TotalPages = (int)Math.Ceiling((double)totalUsers / pageSize),
                TotalUsers = totalUsers,
                AvailableRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync()
            };

            return View(viewModel);
        }

        // GET: UserManagement/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);

            // Get user's order statistics
            var orderCount = await _context.Orders.CountAsync(o => o.UserId == id);
            var totalSpent = await _context.Orders
                .Where(o => o.UserId == id)
                .SumAsync(o => o.OrderTotal);

            var viewModel = new UserDetailsViewModel
            {
                Id = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email ?? "",
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber ?? "",
                AvatarUrl = user.AvatarUrl,
                Roles = roles.ToList(),
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEnd = user.LockoutEnd,
                AccessFailedCount = user.AccessFailedCount,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt,
                Books = await _context.Books.Where(b => b.AuthorId == user.Id).ToListAsync()
            };

            return View(viewModel);
        }

        // GET: UserManagement/Create
        public async Task<IActionResult> Create()
        {
            var viewModel = new CreateUserViewModel
            {
                AvailableRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync()
            };

            return View(viewModel);
        }

        // POST: UserManagement/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    PhoneNumber = model.PhoneNumber,
                    EmailConfirmed = model.EmailConfirmed,
                    TwoFactorEnabled = model.TwoFactorEnabled,
                    LockoutEnabled = model.LockoutEnabled,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Assign roles
                    if (model.SelectedRoles.Any())
                    {
                        await _userManager.AddToRolesAsync(user, model.SelectedRoles);
                    }

                    // Send welcome email if requested
                    if (model.SendWelcomeEmail)
                    {
                        // Implement email sending logic here
                        _logger.LogInformation($"Welcome email should be sent to {user.Email}");
                    }

                    TempData["SuccessMessage"] = $"User '{model.UserName}' created successfully.";
                    return RedirectToAction(nameof(Index));
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            model.AvailableRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync();
            return View(model);
        }

        // GET: UserManagement/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var roles = await _userManager.GetRolesAsync(user);

            var viewModel = new EditUserViewModel
            {
                Id = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email ?? "",
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber ?? "",
                CurrentAvatarUrl = user.AvatarUrl ?? "",
                CurrentRoles = roles.ToList(),
                AvailableRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync(),
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                LockoutEnabled = user.LockoutEnabled,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnd = user.LockoutEnd,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt
            };

            return View(viewModel);
        }

        // POST: UserManagement/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                    return NotFound();

                // Update user properties
                user.UserName = model.UserName;
                user.Email = model.Email;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.PhoneNumber = model.PhoneNumber;
                user.EmailConfirmed = model.EmailConfirmed;
                user.PhoneNumberConfirmed = model.PhoneNumberConfirmed;
                user.LockoutEnabled = model.LockoutEnabled;
                user.TwoFactorEnabled = model.TwoFactorEnabled;
                user.UpdatedAt = DateTime.UtcNow;

                // Handle avatar upload
                if (model.Avatar != null)
                {
                    // Handle file upload here - save to disk/cloud and update AvatarUrl
                    // For now, just keeping the current avatar
                }

                // Handle password change
                if (!string.IsNullOrEmpty(model.NewPassword))
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    await _userManager.ResetPasswordAsync(user, token, model.NewPassword);
                }

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    TempData["SuccessMessage"] = $"User '{model.UserName}' updated successfully.";
                    return RedirectToAction(nameof(Details), new { id = model.Id });
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            model.AvailableRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync();
            return View(model);
        }

        // POST: UserManagement/ToggleLockout/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleLockout(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            if (await _userManager.IsLockedOutAsync(user))
            {
                // Unlock user
                await _userManager.SetLockoutEndDateAsync(user, null);
                await _userManager.ResetAccessFailedCountAsync(user);
                TempData["SuccessMessage"] = $"User '{user.UserName}' has been unlocked.";
            }
            else
            {
                // Lock user for 1 year
                await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(1));
                TempData["SuccessMessage"] = $"User '{user.UserName}' has been locked out.";
            }

            return RedirectToAction(nameof(Details), new { id });
        }

        // GET: UserManagement/ResetPassword/5
        public async Task<IActionResult> ResetPassword(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var viewModel = new ResetPasswordViewModel
            {
                UserId = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email ?? ""
            };

            return View(viewModel);
        }

        // POST: UserManagement/ResetPassword/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user == null)
                    return NotFound();

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

                if (result.Succeeded)
                {
                    if (model.SendNotificationEmail)
                    {
                        // Implement email notification
                        _logger.LogInformation($"Password reset notification should be sent to {user.Email}");
                    }

                    TempData["SuccessMessage"] = $"Password reset successfully for '{user.UserName}'.";
                    return RedirectToAction(nameof(Details), new { id = model.UserId });
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(model);
        }

        // POST: UserManagement/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            // Prevent deleting current user
            var currentUserId = _userManager.GetUserId(User);
            if (user.Id == currentUserId)
            {
                TempData["ErrorMessage"] = "You cannot delete your own account.";
                return RedirectToAction(nameof(Index));
            }

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = $"User '{user.UserName}' deleted successfully.";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to delete user.";
            }

            return RedirectToAction(nameof(Index));
        }

        // GET: UserManagement/ManageRoles/5
        public async Task<IActionResult> ManageRoles(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var currentRoles = await _userManager.GetRolesAsync(user);
            var allRoles = await _roleManager.Roles.ToListAsync();

            var viewModel = new UserRoleManagementViewModel
            {
                UserId = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email ?? "",
                CurrentRoles = currentRoles.ToList(),
                AvailableRoles = allRoles.Select(role => new RoleAssignmentItem
                {
                    RoleName = role.Name!,
                    Description = GetRoleDescription(role.Name!),
                    IsAssigned = currentRoles.Contains(role.Name!)
                }).ToList()
            };

            return View(viewModel);
        }

        // POST: UserManagement/ManageRoles/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRoles(UserRoleManagementViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
                return NotFound();

            var currentRoles = await _userManager.GetRolesAsync(user);
            var selectedRoles = model.AvailableRoles.Where(r => r.IsAssigned).Select(r => r.RoleName).ToList();

            var rolesToRemove = currentRoles.Except(selectedRoles);
            var rolesToAdd = selectedRoles.Except(currentRoles);

            await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
            await _userManager.AddToRolesAsync(user, rolesToAdd);

            TempData["SuccessMessage"] = $"Roles updated successfully for '{user.UserName}'.";
            return RedirectToAction(nameof(Details), new { id = model.UserId });
        }

        // GET: UserManagement/Security/5
        public async Task<IActionResult> Security(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var logins = await _userManager.GetLoginsAsync(user);

            var viewModel = new UserSecurityViewModel
            {
                UserId = user.Id,
                UserName = user.UserName ?? "",
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEnd = user.LockoutEnd,
                AccessFailedCount = user.AccessFailedCount,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                ExternalLogins = logins.ToList()
            };

            return View(viewModel);
        }

        private string GetRoleDescription(string roleName)
        {
            return roleName switch
            {
                "Admin" => "Full system access and user management",
                "Author" => "Can create and manage books",
                "User" => "Standard user with book browsing and ordering",
                _ => "Standard role"
            };
        }
    }
}

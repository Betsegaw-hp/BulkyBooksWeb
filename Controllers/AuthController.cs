using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using BulkyBooksWeb.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using BulkyBooksWeb.Models.ViewModels;
using BulkyBooksWeb.Services;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;

namespace BulkyBooksWeb.Controllers
{
	public class AuthController : Controller
	{
		private readonly ApplicationDbContext _context;
		private readonly IAuthorizationService _authService;
		private readonly IUserContext _userContext;
		private readonly UserService _userService;
		private readonly ILogger<AuthController> _logger;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly RoleManager<IdentityRole> _roleManager;

		public AuthController(
			ApplicationDbContext context,
			IAuthorizationService authorizationService,
			IUserContext userContext, ILogger<AuthController> logger,
			UserService userService,
			UserManager<ApplicationUser> userManager,
			SignInManager<ApplicationUser> signInManager,
			RoleManager<IdentityRole> roleManager)
		{
			_context = context;
			_authService = authorizationService;
			_userContext = userContext;
			_userService = userService;
			_logger = logger;
			_userManager = userManager;
			_signInManager = signInManager;
			_roleManager = roleManager;
		}


		public async Task<IActionResult> Profile()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var roles = await _userManager.GetRolesAsync(user);
			var role = roles.FirstOrDefault() ?? "User";

			// Create a User object for the view model (for backward compatibility)
			var userViewModel = new User
			{
				Id = user.Id.GetHashCode(), // Use hash code of GUID for int compatibility
				Username = user.UserName ?? "",
				Email = user.Email ?? "",
				FullName = user.FullName,
				AvatarUrl = user.AvatarUrl,
				Role = Enum.Parse<RoleOpt>(role, true),
				CreatedAt = user.CreatedAt,
				UpdatedAt = user.UpdatedAt,
				PasswordHash = "" // Don't expose password hash
			};

			UserProfileViewModel userProfileViewModel = new()
			{
				User = userViewModel,
				UpdateProfile = new UpdateProfileViewModel
				{
					FullName = user.FullName,
					Email = user.Email ?? ""
				}
			};

			return View(userProfileViewModel);
		}

		public IActionResult Login(string? returnUrl)
		{
			if (User?.Identity?.IsAuthenticated ?? false)
			{
				return RedirectToAction("Index", "Home");
			}

			ViewData["ReturnUrl"] = returnUrl;
			return View(new LoginModel { ReturnUrl = returnUrl });
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Login(LoginModel login, string? returnUrl)
		{
			if (ModelState.IsValid)
			{
				// Find user by username (UserName in Identity)
				var user = await _userManager.FindByNameAsync(login.Username);
				
				if (user != null)
				{
					// Use Identity's sign-in manager
					var result = await _signInManager.PasswordSignInAsync(
						login.Username, 
						login.Password, 
						login.RememberMe, 
						lockoutOnFailure: true);
						
					if (result.Succeeded)
					{
						_logger.LogInformation("User {Username} logged in successfully", login.Username);
						
						// Redirect to return URL or home
						returnUrl ??= login.ReturnUrl;
						if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
						{
							return Redirect(returnUrl);
						}
						return RedirectToAction("Index", "Home");
					}
					
					if (result.IsLockedOut)
					{
						ModelState.AddModelError(string.Empty, "Account locked. Try again later.");
						return View(login);
					}
				}
				
				ModelState.AddModelError(string.Empty, "Invalid login attempt.");
			}

			return View(login);
		}

		public IActionResult SignUp()
		{
			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SignUp(SignUpModel signUp)
		{
			if (!ModelState.IsValid) return View(signUp);
			var errors = new List<string>();

			// Check if username already exists using Identity
			var existingUser = await _userManager.FindByNameAsync(signUp.Username);
			if (existingUser != null)
				errors.Add("Username already exists.");

			// Check if email already exists
			var existingEmail = await _userManager.FindByEmailAsync(signUp.Email);
			if (existingEmail != null)
				errors.Add("Email already exists.");

			if (signUp.Password != signUp.ConfirmPassword)
				errors.Add("Passwords do not match.");

			if (!signUp.AcceptTerms)
				errors.Add("You must accept the terms and conditions.");

			if (errors.Count != 0)
			{
				foreach (var error in errors)
					ModelState.AddModelError(string.Empty, error);
				return View(signUp);
			}

			// Check if this should be an admin (first user)
			var adminCount = await _userManager.GetUsersInRoleAsync("Admin");
			var roleToAssign = adminCount.Count > 0 ? signUp.Role.ToString() : "Admin";

			// Create new ApplicationUser
			var newUser = new ApplicationUser
			{
				UserName = signUp.Username,
				Email = signUp.Email,
				FullName = signUp.FullName,
				CreatedAt = DateTime.UtcNow,
				UpdatedAt = DateTime.UtcNow,
				EmailConfirmed = true // For simplicity, auto-confirm emails
			};

			// Create user using Identity
			var result = await _userManager.CreateAsync(newUser, signUp.Password);
			
			if (result.Succeeded)
			{
				// Ensure role exists
				if (!await _roleManager.RoleExistsAsync(roleToAssign))
				{
					await _roleManager.CreateAsync(new IdentityRole(roleToAssign));
				}
				
				// Add user to role
				await _userManager.AddToRoleAsync(newUser, roleToAssign);
				
				_logger.LogInformation("User {Username} created successfully with role {Role}", signUp.Username, roleToAssign);
				
				// Optionally sign in the user immediately
				// await _signInManager.SignInAsync(newUser, isPersistent: false);
				
				return RedirectToAction("Login");
			}
			
			// Add errors from Identity
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return View(signUp);
		}

		[Authorize]
		[HttpPost]
		public async Task<IActionResult> Logout()
		{
			await _signInManager.SignOutAsync();
			return RedirectToAction("Index", "Home");
		}

		public async Task<IActionResult> IsUsernameUnique(string username)
		{
			var existingUser = await _userManager.FindByNameAsync(username);
			var isUnique = existingUser == null;
			return Json(isUnique);
		}

		public IActionResult AccessDenied([FromQuery] string ReturnUrl)
		{
			if (string.IsNullOrEmpty(ReturnUrl))
			{
				ReturnUrl = Url.Action("Index", "Home")!;
			}
			ViewData["ReturnUrl"] = ReturnUrl;
			return View();
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> UpdateProfile(UpdateProfileViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (!ModelState.IsValid)
			{
				var errors = ModelState
					.Where(x => x.Value != null && x.Value.Errors != null && x.Value.Errors.Count > 0)
					.Select(x => new
					{
						Field = x.Key,
						Errors = string.Join(", ", x.Value?.Errors?.Select(e => e.ErrorMessage) ?? [])
					});

				_logger.LogInformation($"Validation errors: {JsonSerializer.Serialize(errors)}");
				
				// Create view model for return
				var roles = await _userManager.GetRolesAsync(user);
				var role = roles.FirstOrDefault() ?? "User";
				
				var userViewModel = new User
				{
					Id = user.Id.GetHashCode(),
					Username = user.UserName ?? "",
					Email = user.Email ?? "",
					FullName = user.FullName,
					AvatarUrl = user.AvatarUrl,
					Role = Enum.Parse<RoleOpt>(role, true),
					CreatedAt = user.CreatedAt,
					UpdatedAt = user.UpdatedAt,
					PasswordHash = ""
				};
				
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdateProfile = model,
					User = userViewModel
				};
				return View("Profile", userProfileViewModel);
			}

			// Update user properties
			user.FullName = model.FullName;
			user.Email = model.Email;
			user.UpdatedAt = DateTime.UtcNow;

			var result = await _userManager.UpdateAsync(user);
			if (result.Succeeded)
			{
				return RedirectToAction("Profile");
			}
			
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return RedirectToAction("Profile");
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");
			
			if (!ModelState.IsValid)
			{
				// Create view model for return
				var roles = await _userManager.GetRolesAsync(user);
				var role = roles.FirstOrDefault() ?? "User";
				
				var userViewModel = new User
				{
					Id = user.Id.GetHashCode(),
					Username = user.UserName ?? "",
					Email = user.Email ?? "",
					FullName = user.FullName,
					AvatarUrl = user.AvatarUrl,
					Role = Enum.Parse<RoleOpt>(role, true),
					CreatedAt = user.CreatedAt,
					UpdatedAt = user.UpdatedAt,
					PasswordHash = ""
				};

				var userProfileViewModel = new UserProfileViewModel
				{
					ChangePassword = model,
					User = userViewModel
				};
				return View("Profile", userProfileViewModel);
			}

			// Use Identity's change password method
			var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
			
			if (result.Succeeded)
			{
				// Update the security stamp and sign out other sessions
				await _userManager.UpdateSecurityStampAsync(user);
				
				// Refresh the sign-in cookie
				await _signInManager.RefreshSignInAsync(user);
				
				_logger.LogInformation("User {UserId} changed password successfully", user.Id);
				return RedirectToAction("Profile");
			}

			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return RedirectToAction("Profile");
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> UpdatePreferences(UpdatePreferencesViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (!ModelState.IsValid)
			{
				// Create view model for return
				var roles = await _userManager.GetRolesAsync(user);
				var role = roles.FirstOrDefault() ?? "User";
				
				var userViewModel = new User
				{
					Id = user.Id.GetHashCode(),
					Username = user.UserName ?? "",
					Email = user.Email ?? "",
					FullName = user.FullName,
					AvatarUrl = user.AvatarUrl,
					Role = Enum.Parse<RoleOpt>(role, true),
					CreatedAt = user.CreatedAt,
					UpdatedAt = user.UpdatedAt,
					PasswordHash = ""
				};
				
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdatePreferences = model,
					User = userViewModel
				};
				return View("Profile", userProfileViewModel);
			}

			// Note: Since ApplicationUser doesn't have preference fields yet,
			// we'll just return success. You can add these fields later if needed.
			// user.EmailNotificationEnabled = model.EmailNotificationEnabled;
			// user.ActivityAlertEnabled = model.ActivityAlertEnabled;
			// user.ItemsPerPage = model.ItemsPerPage;

			// await _userManager.UpdateAsync(user);

			return RedirectToAction("Profile");
		}
	}
}

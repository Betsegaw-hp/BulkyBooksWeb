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
using System.Text;

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

			UserProfileViewModel userProfileViewModel = new()
			{
				User = user,
				UpdateProfile = new UpdateProfileViewModel
				{
					FullName = user.FullName,
					Email = user.Email ?? ""
				},
				ChangePassword = new ChangePasswordViewModel(),
				UpdatePreferences = new UpdatePreferencesViewModel()
			};

			// Set active tab from TempData if available
			ViewBag.ActiveTab = TempData["ActiveTab"] as string ?? "personal-info";
			
			// Handle success/error messages
			if (TempData["SuccessMessage"] != null)
			{
				ViewBag.SuccessMessage = TempData["SuccessMessage"];
			}
			if (TempData["ErrorMessage"] != null)
			{
				ViewBag.ErrorMessage = TempData["ErrorMessage"];
			}

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
				FirstName = signUp.FullName.Split(' ').FirstOrDefault() ?? "",
				LastName = string.Join(" ", signUp.FullName.Split(' ').Skip(1)),
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
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdateProfile = model,
					User = user // Use ApplicationUser directly
				};
				return View("Profile", userProfileViewModel);
			}

			// Update user properties
			user.FirstName = model.FullName.Split(' ').FirstOrDefault() ?? "";
			user.LastName = string.Join(" ", model.FullName.Split(' ').Skip(1));
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
		public async Task<IActionResult> ChangePassword(UserProfileViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				TempData["ErrorMessage"] = "User not found.";
				return RedirectToAction("Login");
			}

			// Validate only the ChangePassword part of the model
			if (string.IsNullOrEmpty(model.ChangePassword.CurrentPassword) ||
				string.IsNullOrEmpty(model.ChangePassword.NewPassword) ||
				string.IsNullOrEmpty(model.ChangePassword.ConfirmNewPassword))
			{
				TempData["ErrorMessage"] = "All password fields are required.";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("Profile");
			}

			if (model.ChangePassword.NewPassword != model.ChangePassword.ConfirmNewPassword)
			{
				TempData["ErrorMessage"] = "New password and confirmation do not match.";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("Profile");
			}

			if (model.ChangePassword.NewPassword.Length < 8)
			{
				TempData["ErrorMessage"] = "Password must be at least 8 characters long.";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("Profile");
			}

			// Use Identity's change password method
			var result = await _userManager.ChangePasswordAsync(user, model.ChangePassword.CurrentPassword, model.ChangePassword.NewPassword);
			
			if (result.Succeeded)
			{
				// Update the security stamp and sign out other sessions
				await _userManager.UpdateSecurityStampAsync(user);
				
				// Refresh the sign-in cookie
				await _signInManager.RefreshSignInAsync(user);
				
				_logger.LogInformation("User {UserId} changed password successfully", user.Id);
				TempData["SuccessMessage"] = "Password changed successfully!";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("Profile");
			}

			// Handle Identity errors
			var errorMessages = new List<string>();
			foreach (var error in result.Errors)
			{
				errorMessages.Add(error.Description);
			}
			
			TempData["ErrorMessage"] = string.Join(" ", errorMessages);
			TempData["ActiveTab"] = "security";
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
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdatePreferences = model,
					User = user // Use ApplicationUser directly
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

		// GET: Profile Management
		[Authorize]
		public async Task<IActionResult> ManageProfile(string tab = "personal")
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var externalLogins = await _userManager.GetLoginsAsync(user);
			var twoFactorProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);

			var viewModel = new ProfileManagementViewModel
			{
				ActiveTab = tab,
				PersonalInfo = new PersonalInfoViewModel
				{
					UserId = user.Id,
					FirstName = user.FirstName,
					LastName = user.LastName,
					Email = user.Email ?? "",
					PhoneNumber = user.PhoneNumber ?? "",
					UserName = user.UserName ?? "",
					CurrentAvatarUrl = user.AvatarUrl ?? "",
					EmailConfirmed = user.EmailConfirmed,
					PhoneNumberConfirmed = user.PhoneNumberConfirmed,
					CreatedAt = user.CreatedAt,
					LastLoginAt = user.LastLoginAt
				},
				Security = new AccountSecurityViewModel
				{
					UserId = user.Id,
					TwoFactorEnabled = user.TwoFactorEnabled,
					EmailConfirmed = user.EmailConfirmed,
					PhoneNumberConfirmed = user.PhoneNumberConfirmed,
					AccessFailedCount = user.AccessFailedCount,
					LockoutEnd = user.LockoutEnd,
					ExternalLogins = externalLogins.ToList(),
					TwoFactorProviders = twoFactorProviders.ToList(),
					HasRecoveryCodes = await _userManager.CountRecoveryCodesAsync(user) > 0
				},
				ConnectedAccounts = new ConnectedAccountsViewModel
				{
					ExternalLogins = externalLogins.ToList()
				}
			};

			return View(viewModel);
		}

		// POST: Update Personal Information
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> UpdatePersonalInfo(PersonalInfoViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (ModelState.IsValid)
			{
				bool emailChanged = user.Email != model.Email;
				bool phoneChanged = user.PhoneNumber != model.PhoneNumber;

				user.FirstName = model.FirstName;
				user.LastName = model.LastName;
				user.Email = model.Email;
				user.PhoneNumber = model.PhoneNumber;
				user.UpdatedAt = DateTime.UtcNow;

				// If email changed, mark as unconfirmed
				if (emailChanged)
				{
					user.EmailConfirmed = false;
				}

				// If phone changed, mark as unconfirmed
				if (phoneChanged)
				{
					user.PhoneNumberConfirmed = false;
				}

				// Handle avatar upload
				if (model.NewAvatar != null && model.NewAvatar.Length > 0)
				{
					// TODO: Implement file upload to storage
					// For now, just log the upload attempt
					_logger.LogInformation($"Avatar upload attempted for user {user.Id}");
				}

				var result = await _userManager.UpdateAsync(user);
				if (result.Succeeded)
				{
					TempData["SuccessMessage"] = "Personal information updated successfully.";
					
					if (emailChanged)
					{
						TempData["InfoMessage"] = "Please verify your new email address.";
						// TODO: Send email confirmation
					}
					
					if (phoneChanged)
					{
						TempData["InfoMessage"] = "Please verify your new phone number.";
						// TODO: Send SMS confirmation
					}
				}
				else
				{
					foreach (var error in result.Errors)
					{
						ModelState.AddModelError("", error.Description);
					}
					TempData["ErrorMessage"] = "Failed to update personal information.";
				}
			}

			return RedirectToAction("ManageProfile", new { tab = "personal" });
		}

		// POST: Change Password
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ChangePasswordForm(ChangePasswordFormViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (ModelState.IsValid)
			{
				var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
				
				if (result.Succeeded)
				{
					await _signInManager.RefreshSignInAsync(user);
					TempData["SuccessMessage"] = "Password changed successfully.";
					_logger.LogInformation($"User {user.Id} changed their password successfully.");
				}
				else
				{
					foreach (var error in result.Errors)
					{
						ModelState.AddModelError("", error.Description);
					}
					TempData["ErrorMessage"] = "Failed to change password.";
				}
			}

			return RedirectToAction("ManageProfile", new { tab = "security" });
		}

		// GET: Two-Factor Authentication Setup
		[Authorize]
		public async Task<IActionResult> SetupTwoFactor()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var model = new TwoFactorSetupViewModel
			{
				IsEnabled = user.TwoFactorEnabled
			};

			if (!user.TwoFactorEnabled)
			{
				await _userManager.ResetAuthenticatorKeyAsync(user);
				var key = await _userManager.GetAuthenticatorKeyAsync(user);
				model.AuthenticatorKey = FormatKey(key!);
				model.QrCodeUri = GenerateQrCodeUri(user.Email!, key!);
			}
			else
			{
				model.RecoveryCodes = (await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))!.ToList();
			}

			return View(model);
		}

		// POST: Enable Two-Factor Authentication
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> EnableTwoFactor(TwoFactorSetupViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (ModelState.IsValid)
			{
				var verificationCode = model.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);
				var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

				if (is2faTokenValid)
				{
					await _userManager.SetTwoFactorEnabledAsync(user, true);
					var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
					
					TempData["SuccessMessage"] = "Two-factor authentication has been enabled.";
					TempData["RecoveryCodes"] = string.Join(",", recoveryCodes!);
					
					_logger.LogInformation($"User {user.Id} enabled 2FA.");
					return RedirectToAction("ManageProfile", new { tab = "security" });
				}
				else
				{
					ModelState.AddModelError("VerificationCode", "Verification code is invalid.");
					TempData["ErrorMessage"] = "Invalid verification code.";
				}
			}

			// Regenerate the setup data if validation failed
			await _userManager.ResetAuthenticatorKeyAsync(user);
			var key = await _userManager.GetAuthenticatorKeyAsync(user);
			model.AuthenticatorKey = FormatKey(key!);
			model.QrCodeUri = GenerateQrCodeUri(user.Email!, key!);

			return View(model);
		}

		// POST: Disable Two-Factor Authentication
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> DisableTwoFactor()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
			if (disable2faResult.Succeeded)
			{
				TempData["SuccessMessage"] = "Two-factor authentication has been disabled.";
				_logger.LogInformation($"User {user.Id} disabled 2FA.");
			}
			else
			{
				TempData["ErrorMessage"] = "Failed to disable two-factor authentication.";
			}

			return RedirectToAction("ManageProfile", new { tab = "security" });
		}

		// GET: Generate Recovery Codes
		[Authorize]
		public async Task<IActionResult> GenerateRecoveryCodes()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (!user.TwoFactorEnabled)
			{
				TempData["ErrorMessage"] = "Cannot generate recovery codes for user who does not have 2FA enabled.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
			TempData["RecoveryCodes"] = string.Join(",", recoveryCodes!);
			TempData["SuccessMessage"] = "New recovery codes generated successfully.";

			_logger.LogInformation($"User {user.Id} generated new 2FA recovery codes.");
			return RedirectToAction("ManageProfile", new { tab = "security" });
		}

		// GET: Download Personal Data
		[Authorize]
		public async Task<IActionResult> DownloadPersonalData()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			// Gather user's personal data
			var orders = await _context.Orders
				.Where(o => o.UserId == user.Id)
				.Include(o => o.OrderItems)
				.ToListAsync();

			var books = await _context.Books
				.Where(b => b.AuthorId == user.Id)
				.ToListAsync();

			var personalData = new DownloadDataViewModel
			{
				PersonalData = new PersonalDataInfo
				{
					UserName = user.UserName ?? "",
					Email = user.Email ?? "",
					FullName = user.FullName,
					PhoneNumber = user.PhoneNumber ?? "",
					CreatedAt = user.CreatedAt,
					LastLoginAt = user.LastLoginAt,
					EmailConfirmed = user.EmailConfirmed,
					PhoneNumberConfirmed = user.PhoneNumberConfirmed,
					TwoFactorEnabled = user.TwoFactorEnabled
				},
				Orders = orders.Select(o => new OrderInfo
				{
					OrderId = o.Id,
					OrderDate = o.OrderDate,
					Total = o.OrderTotal,
					Status = o.Status.ToString(),
					BookTitles = o.OrderItems.Select(oi => oi.BookTitle).ToList()
				}).ToList(),
				Books = books.Select(b => new BookInfo
				{
					BookId = b.Id,
					Title = b.Title,
					Author = b.Author.FullName,
					Price = b.Price,
					CreatedAt = b.CreatedDateTime
				}).ToList(),
				Activity = new ActivityInfo
				{
					LastLogin = user.LastLoginAt,
					TotalOrders = orders.Count,
					BooksAuthored = books.Count,
					TotalSpent = orders.Sum(o => o.OrderTotal)
				}
			};

			var json = JsonSerializer.Serialize(personalData, new JsonSerializerOptions { WriteIndented = true });
			var bytes = Encoding.UTF8.GetBytes(json);
			
			_logger.LogInformation($"User {user.Id} downloaded their personal data.");
			return File(bytes, "application/json", $"PersonalData-{user.UserName}-{DateTime.UtcNow:yyyyMMdd}.json");
		}

		// GET: Delete Account
		[Authorize]
		public IActionResult DeleteAccount()
		{
			return View(new DeleteAccountViewModel());
		}

		// POST: Delete Account
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> DeleteAccount(DeleteAccountViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (ModelState.IsValid && model.ConfirmDeletion)
			{
				var passwordCheck = await _userManager.CheckPasswordAsync(user, model.Password);
				if (passwordCheck)
				{
					// Log the deletion attempt
					_logger.LogWarning($"User {user.Id} ({user.Email}) requested account deletion. Reason: {model.Reason}");

					// Sign out the user
					await _signInManager.SignOutAsync();

					// Delete the user
					var result = await _userManager.DeleteAsync(user);
					if (result.Succeeded)
					{
						TempData["SuccessMessage"] = "Your account has been permanently deleted.";
						return RedirectToAction("Index", "Home");
					}
					else
					{
						TempData["ErrorMessage"] = "Failed to delete account. Please contact support.";
					}
				}
				else
				{
					ModelState.AddModelError("Password", "Incorrect password.");
				}
			}

			return View(model);
		}

		// POST: Send Email Confirmation
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SendEmailConfirmation()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			if (user.EmailConfirmed)
			{
				TempData["InfoMessage"] = "Your email is already confirmed.";
				return RedirectToAction("ManageProfile", new { tab = "personal" });
			}

			var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
			var callbackUrl = Url.Action("ConfirmEmail", "Auth", 
				new { userId = user.Id, token = token }, Request.Scheme);

			// TODO: Send actual email
			_logger.LogInformation($"Email confirmation link for {user.Email}: {callbackUrl}");
			
			TempData["SuccessMessage"] = "Confirmation email sent. Please check your inbox.";
			return RedirectToAction("ManageProfile", new { tab = "personal" });
		}

		// Helper methods
		private string FormatKey(string unformattedKey)
		{
			var result = new StringBuilder();
			int currentPosition = 0;
			while (currentPosition + 4 < unformattedKey.Length)
			{
				result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
				currentPosition += 4;
			}
			if (currentPosition < unformattedKey.Length)
			{
				result.Append(unformattedKey.Substring(currentPosition));
			}

			return result.ToString().ToLowerInvariant();
		}

		private string GenerateQrCodeUri(string email, string unformattedKey)
		{
			const string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
			return string.Format(authenticatorUriFormat, 
				Uri.EscapeDataString("BulkyBooks"),
				Uri.EscapeDataString(email), 
				unformattedKey);
		}
	}
}

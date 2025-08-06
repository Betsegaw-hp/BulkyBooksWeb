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
using System.Linq;
using QRCoder;

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


		public IActionResult Profile()
		{
			// Redirect to the more comprehensive ManageProfile page
			return RedirectToAction("ManageProfile");
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
				var user = await _userManager.FindByNameAsync(login.Username);
				
				if (user != null)
				{
					var result = await _signInManager.PasswordSignInAsync(
						login.Username, 
						login.Password, 
						login.RememberMe, 
						lockoutOnFailure: true);
						
					if (result.Succeeded)
					{
						user.LastLoginAt = DateTime.UtcNow;
						await _userManager.UpdateAsync(user);
						
						_logger.LogInformation("User {Username} logged in successfully", login.Username);
						
						// Redirect to return URL or home
						returnUrl ??= login.ReturnUrl;
						if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
						{
							return Redirect(returnUrl);
						}
						return RedirectToAction("Index", "Home");
					}
					
					if (result.RequiresTwoFactor)
					{
						_logger.LogInformation("User {Username} requires 2FA", login.Username);
						return RedirectToAction("LoginWith2fa", new { returnUrl = returnUrl ?? login.ReturnUrl, rememberMe = login.RememberMe });
					}
					
					if (result.IsLockedOut)
					{
						_logger.LogWarning("User {Username} account locked out", login.Username);
						ModelState.AddModelError(string.Empty, "Account locked. Try again later.");
						return View(login);
					}
					
					if (result.IsNotAllowed)
					{
						_logger.LogWarning("User {Username} not allowed to sign in", login.Username);
						
						// Find the user to get their email for resend functionality
						var unverifiedUser = await _userManager.FindByNameAsync(login.Username);
						if (unverifiedUser != null && !unverifiedUser.EmailConfirmed)
						{
							TempData["ErrorMessage"] = "Your email address has not been verified yet. Please check your email or request a new verification link.";
							TempData["Email"] = unverifiedUser.Email;
							TempData["UserId"] = unverifiedUser.Id;
							return RedirectToAction("EmailVerificationRequired");
						}
						else
						{
							ModelState.AddModelError(string.Empty, "Account not verified. Please contact support if this problem persists.");
							return View(login);
						}
					}
				}
				
				ModelState.AddModelError(string.Empty, "Invalid login attempt.");
			}

			return View(login);
		}

		// GET: Two-Factor Authentication Login
		public async Task<IActionResult> LoginWith2fa(bool rememberMe, string? returnUrl = null)
		{
			// Ensure the user has gone through the username & password screen first
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

			if (user == null)
			{
				throw new InvalidOperationException($"Unable to load two-factor authentication user.");
			}

			// Provide default returnUrl if none provided
			returnUrl = returnUrl ?? Url.Action("Index", "Home") ?? "/";

			var model = new LoginWith2faViewModel
			{
				RememberMe = rememberMe,
				ReturnUrl = returnUrl
			};

			ViewData["ReturnUrl"] = returnUrl;

			return View(model);
		}

		// POST: Two-Factor Authentication Login
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string? returnUrl = null)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			// Use returnUrl from model if available, otherwise use parameter, otherwise default to Home
			returnUrl = returnUrl ?? model.ReturnUrl ?? Url.Action("Index", "Home") ?? "/";

			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				throw new InvalidOperationException($"Unable to load two-factor authentication user.");
			}

			var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

			var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);

			var userId = await _userManager.GetUserIdAsync(user);

			if (result.Succeeded)
			{
				// Update last login time
				user.LastLoginAt = DateTime.UtcNow;
				await _userManager.UpdateAsync(user);
				
				_logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", userId);
				
				if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
				{
					return Redirect(returnUrl);
				}
				return RedirectToAction("Index", "Home");
			}
			else if (result.IsLockedOut)
			{
				_logger.LogWarning("User with ID '{UserId}' account locked out.", userId);
				return RedirectToAction("Lockout");
			}
			else
			{
				_logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", userId);
				ModelState.AddModelError("TwoFactorCode", "Invalid authenticator code.");
				
				// Ensure model has proper ReturnUrl for re-rendering
				model.ReturnUrl = returnUrl;
				return View(model);
			}
		}

		// GET: Login with Recovery Code
		public async Task<IActionResult> LoginWithRecoveryCode(string? returnUrl = null)
		{
			// Ensure the user has gone through the username & password screen first
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				throw new InvalidOperationException($"Unable to load two-factor authentication user.");
			}

			// Provide default returnUrl if none provided
			returnUrl = returnUrl ?? Url.Action("Index", "Home") ?? "/";

			ViewData["ReturnUrl"] = returnUrl;

			return View(new TwoFactorRecoveryCodeLoginViewModel { ReturnUrl = returnUrl });
		}

		// POST: Login with Recovery Code
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> LoginWithRecoveryCode(TwoFactorRecoveryCodeLoginViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				throw new InvalidOperationException($"Unable to load two-factor authentication user.");
			}

			var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

			var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

			var userId = await _userManager.GetUserIdAsync(user);

			if (result.Succeeded)
			{
				// Update last login time
				user.LastLoginAt = DateTime.UtcNow;
				await _userManager.UpdateAsync(user);
				
				_logger.LogInformation("User with ID '{UserId}' logged in with a recovery code.", userId);
				
				// Use model ReturnUrl or default to Home
				var returnUrl = model.ReturnUrl ?? Url.Action("Index", "Home") ?? "/";
				
				if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
				{
					return Redirect(returnUrl);
				}
				return RedirectToAction("Index", "Home");
			}
			if (result.IsLockedOut)
			{
				_logger.LogWarning("User with ID '{UserId}' account locked out.", userId);
				return RedirectToAction("Lockout");
			}
			else
			{
				_logger.LogWarning("Invalid recovery code entered for user with ID '{UserId}'", userId);
				ModelState.AddModelError("RecoveryCode", "Invalid recovery code entered.");
				
				// Ensure model has proper ReturnUrl for re-rendering
				model.ReturnUrl = model.ReturnUrl ?? Url.Action("Index", "Home") ?? "/";
				return View(model);
			}
		}

		// GET: Lockout
		public IActionResult Lockout()
		{
			return View();
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
				EmailConfirmed = false, 
				TwoFactorEnabled = false, // Default to false for new users
				LockoutEnabled = true, // Enable lockout protection
				AccessFailedCount = 0
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
				
				// Send email verification
				try
				{
					var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
					var callbackUrl = Url.Action("ConfirmEmail", "Auth", 
						new { userId = newUser.Id, token = token }, Request.Scheme);

					// TODO: Send actual email - for now just log the confirmation link
					_logger.LogInformation($"Email confirmation link for {newUser.Email}: {callbackUrl}");
					
					// Set success message and redirect to email verification page
					TempData["SuccessMessage"] = "Account created successfully! Please check your email to verify your account before signing in.";
					TempData["Email"] = newUser.Email;
					TempData["UserId"] = newUser.Id;
					
					return RedirectToAction("EmailVerificationRequired");
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Error sending welcome email verification for user {UserId}", newUser.Id);
					// Still redirect to verification page even if email sending failed
					TempData["WarningMessage"] = "Account created successfully! However, we couldn't send the verification email. You can request a new one below.";
					TempData["Email"] = newUser.Email;
					TempData["UserId"] = newUser.Id;
					
					return RedirectToAction("EmailVerificationRequired");
				}
			}
			
			// Add errors from Identity
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return View(signUp);
		}

		// GET: Email Verification Required
		[HttpGet]
		public IActionResult EmailVerificationRequired()
		{
			// Pass email and user ID from TempData for resend functionality
			ViewBag.Email = TempData["Email"]?.ToString();
			ViewBag.UserId = TempData["UserId"]?.ToString();
			return View();
		}

		// POST: Resend Email Verification
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResendEmailVerification(string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				TempData["ErrorMessage"] = "Email address is required.";
				return RedirectToAction("EmailVerificationRequired");
			}

			var user = await _userManager.FindByEmailAsync(email);
			if (user == null)
			{
				// Don't reveal that the user does not exist
				TempData["SuccessMessage"] = "If an account with that email exists, a verification email has been sent.";
				return RedirectToAction("EmailVerificationRequired");
			}

			if (user.EmailConfirmed)
			{
				TempData["InfoMessage"] = "This email address is already verified. You can now sign in.";
				return RedirectToAction("Login");
			}

			try
			{
				var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
				var callbackUrl = Url.Action("ConfirmEmail", "Auth", 
					new { userId = user.Id, token = token }, Request.Scheme);

				// TODO: Send actual email - for now just log the confirmation link
				_logger.LogInformation($"Email confirmation link for {user.Email}: {callbackUrl}");
				
				TempData["SuccessMessage"] = "Verification email sent! Please check your inbox.";
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error resending email verification for user {UserId}", user.Id);
				TempData["ErrorMessage"] = "Failed to send verification email. Please try again.";
			}

			return RedirectToAction("EmailVerificationRequired");
		}

		// GET: Email Verification Success
		[HttpGet]
		public IActionResult EmailVerificationSuccess()
		{
			ViewBag.Email = TempData["Email"]?.ToString();
			return View();
		}

		// GET: Forgot Password
		[HttpGet]
		public IActionResult ForgotPassword()
		{
			return View();
		}

		// POST: Forgot Password
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			var user = await _userManager.FindByEmailAsync(model.Email);
			
			// Don't reveal whether the user exists or not for security
			TempData["SuccessMessage"] = "If an account with that email exists, a password reset link has been sent.";
			
			if (user != null && user.EmailConfirmed)
			{
				try
				{
					var token = await _userManager.GeneratePasswordResetTokenAsync(user);
					var callbackUrl = Url.Action("ResetPassword", "Auth", 
						new { userId = user.Id, token = token }, Request.Scheme);

					// TODO: Send actual email - for now just log the reset link
					_logger.LogInformation($"Password reset link for {user.Email}: {callbackUrl}");
					
					_logger.LogInformation("Password reset requested for user {UserId}", user.Id);
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Error sending password reset email for user {Email}", model.Email);
				}
			}
			else if (user != null && !user.EmailConfirmed)
			{
				_logger.LogWarning("Password reset requested for unverified user {Email}", model.Email);
			}
			else
			{
				_logger.LogWarning("Password reset requested for non-existent email {Email}", model.Email);
			}

			return RedirectToAction("ForgotPasswordConfirmation");
		}

		// GET: Forgot Password Confirmation
		[HttpGet]
		public IActionResult ForgotPasswordConfirmation()
		{
			return View();
		}

		// GET: Reset Password
		[HttpGet]
		public IActionResult ResetPassword(string userId, string token)
		{
			if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
			{
				TempData["ErrorMessage"] = "Invalid password reset link.";
				return RedirectToAction("Login");
			}

			var model = new ResetPasswordViewModel
			{
				Token = token,
				UserId = userId
			};

			return View(model);
		}

		// POST: Reset Password
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			var user = await _userManager.FindByIdAsync(model.UserId);
			if (user == null)
			{
				TempData["ErrorMessage"] = "Invalid password reset request.";
				return RedirectToAction("Login");
			}

			var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
			if (result.Succeeded)
			{
				// Update security stamp to invalidate existing sessions
				await _userManager.UpdateSecurityStampAsync(user);
				
				_logger.LogInformation("User {UserId} reset their password successfully", user.Id);
				TempData["SuccessMessage"] = "Your password has been reset successfully. Please sign in with your new password.";
				return RedirectToAction("Login");
			}

			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return View(model);
		}

		// POST: External Login
		[HttpPost]
		[ValidateAntiForgeryToken]
		public IActionResult ExternalLogin(string provider, string? returnUrl = null)
		{
			// Request a redirect to the external login provider
			var redirectUrl = Url.Action("ExternalLoginCallback", "Auth", new { ReturnUrl = returnUrl });
			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
			return new ChallengeResult(provider, properties);
		}

		// GET: External Login Callback
		[HttpGet]
		public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");

			if (remoteError != null)
			{
				TempData["ErrorMessage"] = $"Error from external provider: {remoteError}";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}

			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				TempData["ErrorMessage"] = "Error loading external login information.";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}

			// Sign in the user with this external login provider if the user already has a login
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
			if (result.Succeeded)
			{
				_logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
				return LocalRedirect(returnUrl);
			}
			if (result.IsLockedOut)
			{
				return RedirectToAction("Lockout");
			}
			else
			{
				// If the user does not have an account, then create one
				ViewData["ReturnUrl"] = returnUrl;
				ViewData["LoginProvider"] = info.LoginProvider;
				
				var email = info.Principal.FindFirstValue(ClaimTypes.Email);
				var name = info.Principal.FindFirstValue(ClaimTypes.Name) ?? "";
				
				return View("ExternalLogin", new ExternalLoginViewModel 
				{ 
					Email = email ?? "", 
					FullName = name,
					ReturnUrl = returnUrl ?? "",
					LoginProvider = info.LoginProvider
				});
			}
		}

		// POST: External Login Confirmation
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string? returnUrl = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");

			// Get the information about the user from the external login provider
			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				TempData["ErrorMessage"] = "Error loading external login information during confirmation.";
				ViewData["LoginProvider"] = model.LoginProvider;
				return View("ExternalLogin", model);
			}

			if (ModelState.IsValid)
			{
				// Check if email already exists
				var existingUser = await _userManager.FindByEmailAsync(model.Email);
				if (existingUser != null)
				{
					ModelState.AddModelError("Email", "A user with this email already exists.");
					ViewData["ReturnUrl"] = returnUrl;
					ViewData["LoginProvider"] = model.LoginProvider;
					return View("ExternalLogin", model);
				}

				var user = new ApplicationUser 
				{ 
					UserName = model.Email,
					Email = model.Email,
					FirstName = model.FullName.Split(' ').FirstOrDefault() ?? "",
					LastName = string.Join(" ", model.FullName.Split(' ').Skip(1)),
					// Only mark email as confirmed if it matches the OAuth provider's email
					EmailConfirmed = model.Email.Equals(info.Principal.FindFirstValue(ClaimTypes.Email), StringComparison.OrdinalIgnoreCase),
					CreatedAt = DateTime.UtcNow,
					UpdatedAt = DateTime.UtcNow
				};

				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					result = await _userManager.AddLoginAsync(user, info);
					if (result.Succeeded)
					{
						// Assign the selected role from the form
						string roleName = model.Role.ToString();
						await _userManager.AddToRoleAsync(user, roleName);
						
						if (!user.EmailConfirmed)
						{
							try
							{
								var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
								var callbackUrl = Url.Action("ConfirmEmail", "Auth", 
									new { userId = user.Id, token = token }, Request.Scheme);

								// TODO: Send actual email - for now just log the confirmation link
								_logger.LogInformation($"Email confirmation link for {user.Email}: {callbackUrl}");
								
								_logger.LogInformation("User created an account using {Name} provider with role {Role}. Email verification required.", info.LoginProvider, roleName);
							}
							catch (Exception ex)
							{
								_logger.LogError(ex, "Error sending email verification for OAuth user {UserId}", user.Id);
							}
						}
						else
						{
							_logger.LogInformation("User created an account using {Name} provider with role {Role}. Email pre-verified.", info.LoginProvider, roleName);
						}
						
						await _signInManager.SignInAsync(user, isPersistent: false);
						return LocalRedirect(returnUrl);
					}
				}
				
				foreach (var error in result.Errors)
				{
					ModelState.AddModelError(string.Empty, error.Description);
				}
			}

			ViewData["ReturnUrl"] = returnUrl;
			ViewData["LoginProvider"] = model.LoginProvider;
			return View("ExternalLogin", model);
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
		public async Task<IActionResult> UpdateProfile(UserProfileViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				TempData["ErrorMessage"] = "User not found.";
				return RedirectToAction("ManageProfile");
			}

			// Validate only the UpdateProfile part of the model
			if (string.IsNullOrEmpty(model.UpdateProfile.FullName) || string.IsNullOrEmpty(model.UpdateProfile.Email))
			{
				TempData["ErrorMessage"] = "Full name and email are required.";
				TempData["ActiveTab"] = "personal-info";
				return RedirectToAction("ManageProfile");
			}

			// Validate email format
			if (!System.Text.RegularExpressions.Regex.IsMatch(model.UpdateProfile.Email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
			{
				TempData["ErrorMessage"] = "Please enter a valid email address.";
				TempData["ActiveTab"] = "personal-info";
				return RedirectToAction("ManageProfile");
			}

			// Check if email is being changed and if it's already taken by another user
			if (user.Email != model.UpdateProfile.Email)
			{
				var existingUser = await _userManager.FindByEmailAsync(model.UpdateProfile.Email);
				if (existingUser != null && existingUser.Id != user.Id)
				{
					TempData["ErrorMessage"] = "This email address is already in use by another account.";
					TempData["ActiveTab"] = "personal-info";
					return RedirectToAction("ManageProfile");
				}
			}

			// Update user properties
			user.FirstName = model.UpdateProfile.FullName.Split(' ').FirstOrDefault() ?? "";
			user.LastName = string.Join(" ", model.UpdateProfile.FullName.Split(' ').Skip(1));
			
			// If email is being changed, mark it as unconfirmed
			bool emailChanged = user.Email != model.UpdateProfile.Email;
			if (emailChanged)
			{
				user.Email = model.UpdateProfile.Email;
				user.EmailConfirmed = false;
				user.NormalizedEmail = _userManager.NormalizeEmail(model.UpdateProfile.Email);
			}
			
			user.UpdatedAt = DateTime.UtcNow;

			var result = await _userManager.UpdateAsync(user);
			if (result.Succeeded)
			{
				if (emailChanged)
				{
					TempData["SuccessMessage"] = "Profile updated successfully! Please verify your new email address.";
					TempData["ActiveTab"] = "verification";
				}
				else
				{
					TempData["SuccessMessage"] = "Profile updated successfully!";
					TempData["ActiveTab"] = "personal-info";
				}
				return RedirectToAction("ManageProfile");
			}

			// Handle Identity errors
			var errorMessages = new List<string>();
			foreach (var error in result.Errors)
			{
				errorMessages.Add(error.Description);
			}
			
			TempData["ErrorMessage"] = string.Join(" ", errorMessages);
			TempData["ActiveTab"] = "personal-info";
			return RedirectToAction("ManageProfile");
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> AddPhoneNumber(string phoneNumber)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				return Json(new { success = false, message = "User not found." });
			}

			// Validate phone number format
			if (string.IsNullOrWhiteSpace(phoneNumber))
			{
				return Json(new { success = false, message = "Phone number is required." });
			}

			// Basic phone number validation (accepts various formats)
			if (!System.Text.RegularExpressions.Regex.IsMatch(phoneNumber.Trim(), @"^[\+]?[\d\s\-\(\)]{10,15}$"))
			{
				return Json(new { success = false, message = "Please enter a valid phone number." });
			}

			// Check if phone number is already taken by another user
			var existingUser = await _userManager.Users
				.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber.Trim() && u.Id != user.Id);
			if (existingUser != null)
			{
				return Json(new { success = false, message = "This phone number is already associated with another account." });
			}

			// Update user's phone number
			user.PhoneNumber = phoneNumber.Trim();
			user.PhoneNumberConfirmed = false; // Require verification
			user.UpdatedAt = DateTime.UtcNow;

			var result = await _userManager.UpdateAsync(user);
			if (result.Succeeded)
			{
				_logger.LogInformation("User {UserId} added phone number successfully", user.Id);
				return Json(new { success = true, message = "Phone number added successfully! Please verify it to complete the process." });
			}

			// Handle Identity errors
			var errorMessages = result.Errors.Select(e => e.Description).ToList();
			return Json(new { success = false, message = string.Join(" ", errorMessages) });
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ChangePhoneNumber(string phoneNumber)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				return Json(new { success = false, message = "User not found." });
			}

			// Validate phone number format
			if (string.IsNullOrWhiteSpace(phoneNumber))
			{
				return Json(new { success = false, message = "Phone number is required." });
			}

			// Basic phone number validation (accepts various formats)
			if (!System.Text.RegularExpressions.Regex.IsMatch(phoneNumber.Trim(), @"^[\+]?[\d\s\-\(\)]{10,15}$"))
			{
				return Json(new { success = false, message = "Please enter a valid phone number." });
			}

			// Check if phone number is already taken by another user
			var existingUser = await _userManager.Users
				.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber.Trim() && u.Id != user.Id);
			if (existingUser != null)
			{
				return Json(new { success = false, message = "This phone number is already associated with another account." });
			}

			// Check if it's the same phone number
			if (user.PhoneNumber == phoneNumber.Trim())
			{
				return Json(new { success = false, message = "This is already your current phone number." });
			}

			// Update user's phone number
			user.PhoneNumber = phoneNumber.Trim();
			user.PhoneNumberConfirmed = false; // Require verification for new number
			user.UpdatedAt = DateTime.UtcNow;

			var result = await _userManager.UpdateAsync(user);
			if (result.Succeeded)
			{
				_logger.LogInformation("User {UserId} changed phone number to {PhoneNumber}", user.Id, phoneNumber.Trim());
				return Json(new { success = true, message = "Phone number updated successfully! Please verify your new number to complete the process." });
			}

			// Handle Identity errors
			var errorMessages = result.Errors.Select(e => e.Description).ToList();
			return Json(new { success = false, message = string.Join(" ", errorMessages) });
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
				return RedirectToAction("ManageProfile");
			}

			if (model.ChangePassword.NewPassword != model.ChangePassword.ConfirmNewPassword)
			{
				TempData["ErrorMessage"] = "New password and confirmation do not match.";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("ManageProfile");
			}

			if (model.ChangePassword.NewPassword.Length < 8)
			{
				TempData["ErrorMessage"] = "Password must be at least 8 characters long.";
				TempData["ActiveTab"] = "security";
				return RedirectToAction("ManageProfile");
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
				return RedirectToAction("ManageProfile");
			}

			// Handle Identity errors
			var errorMessages = new List<string>();
			foreach (var error in result.Errors)
			{
				errorMessages.Add(error.Description);
			}
			
			TempData["ErrorMessage"] = string.Join(" ", errorMessages);
			TempData["ActiveTab"] = "security";
			return RedirectToAction("ManageProfile");
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

			return RedirectToAction("ManageProfile");
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
				
				// Set the properties that the view expects
				model.AuthenticatorKey = key!;
				model.ManualEntryKey = FormatKey(key!);
				model.QrCodeUri = GenerateQrCodeUri(user.Email!, key!);
				model.QrCodeImageData = GenerateQrCodeImage(model.QrCodeUri);
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
					
					// Create a new model for success display
					var successModel = new TwoFactorSetupViewModel 
					{ 
						IsEnabled = true,
						RecoveryCodes = recoveryCodes!.ToList()
					};
					
					// Also set ViewBag for backward compatibility
					ViewBag.RecoveryCodes = recoveryCodes!.ToList();
					TempData["SuccessMessage"] = "Two-factor authentication has been enabled successfully! Please save your recovery codes.";
					
					_logger.LogInformation($"User {user.Id} enabled 2FA.");
					return View("SetupTwoFactor", successModel);
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
			model.AuthenticatorKey = key!;
			model.ManualEntryKey = FormatKey(key!);
			model.QrCodeUri = GenerateQrCodeUri(user.Email!, key!);
			model.QrCodeImageData = GenerateQrCodeImage(model.QrCodeUri);

			return View(model);
		}

		// POST: Disable Two-Factor Authentication
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> DisableTwoFactor()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				// Check if it's an AJAX request
				if (Request.Headers.ContainsKey("X-Requested-With") || 
					Request.Headers["Content-Type"].ToString().Contains("application/json"))
				{
					return Json(new { success = false, message = "User not found." });
				}
				return RedirectToAction("Login");
			}

			var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
			
			
			if (disable2faResult.Succeeded)
			{
				_logger.LogInformation($"User {user.Id} disabled 2FA.");
				
				// Check if it's an AJAX request
				if (Request.Headers.ContainsKey("X-Requested-With") || 
					Request.Headers["Content-Type"].ToString().Contains("application/json"))
				{
					return Json(new { success = true, message = "Two-factor authentication has been disabled." });
				}
				
				TempData["SuccessMessage"] = "Two-factor authentication has been disabled.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}
			else
			{
				// Check if it's an AJAX request
				if (Request.Headers.ContainsKey("X-Requested-With") || 
					Request.Headers["Content-Type"].ToString().Contains("application/json"))
				{
					return Json(new { success = false, message = "Failed to disable two-factor authentication." });
				}
				
				TempData["ErrorMessage"] = "Failed to disable two-factor authentication.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}
		}

		// GET: Generate Recovery Codes
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> GenerateRecoveryCodes()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				// Check if it's an AJAX request
				if (Request.Headers.ContainsKey("X-Requested-With") || 
					Request.Headers["Content-Type"].ToString().Contains("application/json"))
				{
					return Json(new { success = false, message = "User not found." });
				}
				return RedirectToAction("Login");
			}

			if (!user.TwoFactorEnabled)
			{
				// Check if it's an AJAX request
				if (Request.Headers.ContainsKey("X-Requested-With") || 
					Request.Headers["Content-Type"].ToString().Contains("application/json"))
				{
					return Json(new { success = false, message = "Cannot generate recovery codes for user who does not have 2FA enabled." });
				}
				TempData["ErrorMessage"] = "Cannot generate recovery codes for user who does not have 2FA enabled.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
			_logger.LogInformation($"User {user.Id} generated new 2FA recovery codes.");
			
			// Store recovery codes in TempData for both AJAX and form submissions
			TempData["RecoveryCodes"] = string.Join(",", recoveryCodes!);
			TempData["SuccessMessage"] = "New recovery codes generated successfully.";
			
			// Check if it's an AJAX request
			if (Request.Headers.ContainsKey("X-Requested-With") || 
				Request.Headers["Content-Type"].ToString().Contains("application/json"))
			{
				var redirectUrl = Url.Action("ShowRecoveryCodes", "Auth");
				return Json(new { success = true, message = "New recovery codes generated successfully.", redirectUrl = redirectUrl });
			}
			
			return RedirectToAction("ShowRecoveryCodes");
		}

		// GET: Show Recovery Codes
		[Authorize]
		public IActionResult ShowRecoveryCodes()
		{
			if (TempData["RecoveryCodes"] == null)
			{
				TempData["ErrorMessage"] = "No recovery codes available. Please generate new ones.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			var recoveryCodesString = TempData["RecoveryCodes"] as string;
			var recoveryCodes = recoveryCodesString?.Split(',').ToList() ?? new List<string>();
			
			ViewBag.RecoveryCodes = recoveryCodes;
			return View();
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
			if (user == null) 
			{
				if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
				{
					return Json(new { success = false, message = "User not found." });
				}
				return RedirectToAction("Login");
			}

			if (user.EmailConfirmed)
			{
				if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
				{
					return Json(new { success = false, message = "Your email is already confirmed." });
				}
				TempData["InfoMessage"] = "Your email is already confirmed.";
				return RedirectToAction("ManageProfile", new { tab = "personal" });
			}

			try
			{
				var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
				var callbackUrl = Url.Action("ConfirmEmail", "Auth", 
					new { userId = user.Id, token = token }, Request.Scheme);

				// TODO: Send actual email - for now just log the confirmation link
				_logger.LogInformation($"Email confirmation link for {user.Email}: {callbackUrl}");
				
				if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
				{
					return Json(new { success = true, message = "Confirmation email sent. Please check your inbox." });
				}
				
				TempData["SuccessMessage"] = "Confirmation email sent. Please check your inbox.";
				return RedirectToAction("ManageProfile", new { tab = "personal" });
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error sending email confirmation for user {UserId}", user.Id);
				
				if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
				{
					return Json(new { success = false, message = "Failed to send confirmation email. Please try again." });
				}
				
				TempData["ErrorMessage"] = "Failed to send confirmation email. Please try again.";
				return RedirectToAction("ManageProfile", new { tab = "personal" });
			}
		}

		// GET: Confirm Email
		[HttpGet]
		public async Task<IActionResult> ConfirmEmail(string userId, string token)
		{
			if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
			{
				TempData["ErrorMessage"] = "Invalid email confirmation link.";
				return RedirectToAction("Login");
			}

			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				TempData["ErrorMessage"] = "User not found.";
				return RedirectToAction("Login");
			}

			if (user.EmailConfirmed)
			{
				TempData["InfoMessage"] = "Your email is already confirmed. You can now sign in.";
				return RedirectToAction("Login");
			}

			try
			{
				var result = await _userManager.ConfirmEmailAsync(user, token);
				if (result.Succeeded)
				{
					_logger.LogInformation("User {UserId} confirmed their email successfully", user.Id);
					
					// Check if user is logged in (existing user managing profile vs new user confirming)
					if (User.Identity?.IsAuthenticated == true)
					{
						TempData["SuccessMessage"] = "Thank you for confirming your email address!";
						return RedirectToAction("ManageProfile", new { tab = "verification" });
					}
					else
					{
						// New user verification - redirect to welcome page then login
						TempData["SuccessMessage"] = "Email verified successfully! You can now sign in to your account.";
						TempData["Email"] = user.Email;
						return RedirectToAction("EmailVerificationSuccess");
					}
				}
				else
				{
					_logger.LogWarning("Email confirmation failed for user {UserId}: {Errors}", 
						user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
					TempData["ErrorMessage"] = "Email confirmation failed. The link may be expired or invalid.";
					
					if (User.Identity?.IsAuthenticated == true)
					{
						return RedirectToAction("ManageProfile", new { tab = "verification" });
					}
					else
					{
						return RedirectToAction("EmailVerificationRequired");
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error confirming email for user {UserId}", user.Id);
				TempData["ErrorMessage"] = "An error occurred while confirming your email. Please try again.";
				
				if (User.Identity?.IsAuthenticated == true)
				{
					return RedirectToAction("ManageProfile", new { tab = "verification" });
				}
				else
				{
					return RedirectToAction("EmailVerificationRequired");
				}
			}
		}

		// POST: Send Phone Verification
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SendPhoneVerification()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				return Json(new { success = false, message = "User not found." });
			}

			if (string.IsNullOrEmpty(user.PhoneNumber))
			{
				return Json(new { success = false, message = "No phone number to verify. Please add a phone number first." });
			}

			if (user.PhoneNumberConfirmed)
			{
				return Json(new { success = false, message = "Your phone number is already verified." });
			}

			// Generate phone verification token
			var token = await _userManager.GenerateChangePhoneNumberTokenAsync(user, user.PhoneNumber);
			
			// TODO: Send actual SMS with verification code
			// For now, we'll just log it for development purposes
			_logger.LogInformation($"Phone verification code for {user.PhoneNumber}: {token}");
			
			
			return Json(new { success = true, message = $"Verification code sent to {user.PhoneNumber}. Please check your messages. (DEV: Code is {token})" });
		}

		// POST: Verify Phone Number
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> VerifyPhoneNumber(string code)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) 
			{
				return Json(new { success = false, message = "User not found." });
			}

			if (string.IsNullOrEmpty(user.PhoneNumber))
			{
				return Json(new { success = false, message = "No phone number to verify. Please add a phone number first." });
			}

			if (user.PhoneNumberConfirmed)
			{
				return Json(new { success = false, message = "Your phone number is already verified." });
			}

			if (string.IsNullOrWhiteSpace(code))
			{
				return Json(new { success = false, message = "Verification code is required." });
			}

			// Verify the phone number token
			var isValid = await _userManager.VerifyChangePhoneNumberTokenAsync(user, code, user.PhoneNumber);
			
			if (isValid)
			{
				// Mark phone number as confirmed
				user.PhoneNumberConfirmed = true;
				user.UpdatedAt = DateTime.UtcNow;

				var result = await _userManager.UpdateAsync(user);
				if (result.Succeeded)
				{
					_logger.LogInformation("User {UserId} verified phone number successfully", user.Id);
					return Json(new { success = true, message = "Phone number verified successfully!" });
				}

				// Handle Identity errors
				var errorMessages = result.Errors.Select(e => e.Description).ToList();
				return Json(new { success = false, message = string.Join(" ", errorMessages) });
			}

			return Json(new { success = false, message = "Invalid verification code. Please check the code and try again." });
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

		private string GenerateQrCodeImage(string qrCodeUri)
		{
			using var qrGenerator = new QRCodeGenerator();
			using var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
			using var qrCode = new PngByteQRCode(qrCodeData);
			var qrCodeBytes = qrCode.GetGraphic(20);
			return Convert.ToBase64String(qrCodeBytes);
		}
	}
}

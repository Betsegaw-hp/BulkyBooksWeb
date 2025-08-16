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

		public IActionResult Login(string? returnUrl, string? error = null)
		{
			if (User?.Identity?.IsAuthenticated ?? false)
			{
				return RedirectToAction("Index", "Home");
			}

			// Handle error messages from OAuth failures
			if (!string.IsNullOrEmpty(error))
			{
				ModelState.AddModelError(string.Empty, error);
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
		public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null, string? error = null, string? error_description = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");

			// Handle OAuth errors that come as query parameters (e.g., when user cancels)
			if (!string.IsNullOrEmpty(error))
			{
				string errorMessage = error switch
				{
					"access_denied" => "Login was cancelled. You can try again or sign in with a different method.",
					"invalid_request" => "Invalid login request. Pleas					dotnet watch rune try again.",
					"unauthorized_client" => "This application is not authorized for this login method.",
					"unsupported_response_type" => "Login method not supported.",
					"invalid_scope" => "Requested permissions are not available.",
					"server_error" => "The login provider encountered an error. Please try again.",
					"temporarily_unavailable" => "The login provider is temporarily unavailable. Please try again later.",
					_ => $"Login failed: {error_description ?? error}"
				};
				
				_logger.LogWarning("External login failed with error: {Error}, description: {ErrorDescription}", error, error_description);
				TempData["ErrorMessage"] = errorMessage;
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}

			// Handle remote errors from the authentication middleware
			if (remoteError != null)
			{
				_logger.LogWarning("External login failed with remote error: {RemoteError}", remoteError);
				TempData["ErrorMessage"] = $"Error from external provider: {remoteError}";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}

			ExternalLoginInfo? info;
			try
			{
				info = await _signInManager.GetExternalLoginInfoAsync();
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Exception occurred while getting external login info");
				TempData["ErrorMessage"] = "An error occurred during login. Please try again.";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}
			
			if (info == null)
			{
				_logger.LogWarning("External login info was null, possibly due to user cancellation or provider error");
				TempData["ErrorMessage"] = "Login was cancelled or an error occurred. Please try again.";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}

			// Sign in the user with this external login provider if the user already has a login
			Microsoft.AspNetCore.Identity.SignInResult result;
			try
			{
				result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Exception occurred during external login sign-in for provider {Provider}", info.LoginProvider);
				TempData["ErrorMessage"] = "An error occurred during login. Please try again.";
				return RedirectToAction("Login", new { ReturnUrl = returnUrl });
			}
			
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
				
				// Suggest a username based on email or name
				string suggestedUsername = await GenerateUniqueUsernameAsync(email, name);
				
				return View("ExternalLogin", new ExternalLoginViewModel 
				{ 
					Email = email ?? "", 
					FullName = name,
					UserName = suggestedUsername,
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
				// Validate that we have a proper email address
				if (string.IsNullOrWhiteSpace(model.Email))
				{
					_logger.LogWarning("External login confirmation attempted with empty email for provider {Provider}", info.LoginProvider);
					ModelState.AddModelError("Email", "Email address is required.");
					ViewData["ReturnUrl"] = returnUrl;
					ViewData["LoginProvider"] = model.LoginProvider;
					return View("ExternalLogin", model);
				}
				
				_logger.LogInformation("Processing external login confirmation for {Provider}:{ProviderKey} with email {Email}", 
					info.LoginProvider, info.ProviderKey, model.Email);
				
				// FIRST: Check if this specific external login already exists (most specific check)
				var existingUserForThisLogin = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
				if (existingUserForThisLogin != null)
				{
					// This external login is already registered - sign them in
					_logger.LogInformation("External login {Provider}:{ProviderKey} is already registered to user {UserId}. Signing in.", 
						info.LoginProvider, info.ProviderKey, existingUserForThisLogin.Id);
					await _signInManager.SignInAsync(existingUserForThisLogin, isPersistent: false);
					return LocalRedirect(returnUrl);
				}
				
				// SECOND: Check if email already exists with a different user
				var existingUserWithEmail = await _userManager.FindByEmailAsync(model.Email);
				if (existingUserWithEmail != null)
				{
					// Email exists but external login doesn't - this is a conflict
					_logger.LogWarning("External login confirmation failed: Email {Email} already exists for different user {UserId} but external login {Provider}:{ProviderKey} is not linked", 
						model.Email, existingUserWithEmail.Id, info.LoginProvider, info.ProviderKey);
					ModelState.AddModelError("Email", "A user with this email already exists.");
					ViewData["ReturnUrl"] = returnUrl;
					ViewData["LoginProvider"] = model.LoginProvider;
					return View("ExternalLogin", model);
				}

				// THIRD: Check if username already exists
				var existingUserWithUsername = await _userManager.FindByNameAsync(model.UserName);
				if (existingUserWithUsername != null)
				{
					_logger.LogWarning("External login confirmation failed: Username {Username} already exists", model.UserName);
					ModelState.AddModelError("UserName", "This username is already taken. Please choose another one.");
					ViewData["ReturnUrl"] = returnUrl;
					ViewData["LoginProvider"] = model.LoginProvider;
					return View("ExternalLogin", model);
				}

				var user = new ApplicationUser 
				{ 
					UserName = model.UserName,  // Use the chosen username instead of email
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
					_logger.LogInformation("Successfully created new user {UserId} with email {Email} via {Provider} external login", 
						user.Id, user.Email, info.LoginProvider);
						
					result = await _userManager.AddLoginAsync(user, info);
					if (result.Succeeded)
					{
						// Assign the selected role from the form
						string roleName = model.Role.ToString();
						await _userManager.AddToRoleAsync(user, roleName);
						
						_logger.LogInformation("Added role {Role} to user {UserId} and linked external login for {Provider}", 
							roleName, user.Id, info.LoginProvider);
						
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
								
								// Don't sign in the user if email needs verification
								TempData["SuccessMessage"] = "Account created successfully! Please check your email to verify your account before signing in.";
								TempData["Email"] = user.Email;
								TempData["UserId"] = user.Id;
								
								return RedirectToAction("EmailVerificationRequired");
							}
							catch (Exception ex)
							{
								_logger.LogError(ex, "Error sending email verification for OAuth user {UserId}", user.Id);
								
								// Still redirect to verification page even if email sending failed
								TempData["WarningMessage"] = "Account created successfully! However, we couldn't send the verification email. You can request a new one below.";
								TempData["Email"] = user.Email;
								TempData["UserId"] = user.Id;
								
								return RedirectToAction("EmailVerificationRequired");
							}
						}
						else
						{
							_logger.LogInformation("User created an account using {Name} provider with role {Role}. Email pre-verified.", info.LoginProvider, roleName);
							// Only sign in if email is verified (matches OAuth provider email)
							await _signInManager.SignInAsync(user, isPersistent: false);
							return LocalRedirect(returnUrl);
						}
					}
				}
				else
				{
					_logger.LogError("Failed to create user with email {Email} via {Provider} external login. Errors: {Errors}", 
						model.Email, info.LoginProvider, string.Join(", ", result.Errors.Select(e => e.Description)));
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
			var hasPassword = await _userManager.HasPasswordAsync(user);

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
					HasRecoveryCodes = await _userManager.CountRecoveryCodesAsync(user) > 0,
					HasPassword = hasPassword
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
		public async Task<IActionResult> UpdatePersonalInfo(ProfileManagementViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			// Debug logging - log the raw form data
			_logger.LogInformation("UpdatePersonalInfo called for user {UserId}. Raw form data:", user.Id);
			foreach (var item in Request.Form)
			{
				_logger.LogInformation("Form key: '{Key}' = '{Value}'", item.Key, string.Join(", ", item.Value.ToArray()));
			}

			// Get the personal info from the nested model
			var personalInfo = model.PersonalInfo;

			_logger.LogInformation("UpdatePersonalInfo called for user {UserId}. Model: FirstName='{FirstName}', LastName='{LastName}', Email='{Email}', PhoneNumber='{PhoneNumber}'", 
				user.Id, personalInfo.FirstName, personalInfo.LastName, personalInfo.Email, personalInfo.PhoneNumber);
			
			_logger.LogInformation("Current user data: FirstName='{FirstName}', LastName='{LastName}', Email='{Email}', PhoneNumber='{PhoneNumber}'", 
				user.FirstName, user.LastName, user.Email, user.PhoneNumber);

			// Validate only the PersonalInfo part of the model
			if (TryValidateModel(personalInfo, nameof(model.PersonalInfo)))
			{
				bool emailChanged = user.Email != personalInfo.Email;
				bool phoneChanged = user.PhoneNumber != personalInfo.PhoneNumber;
				bool nameChanged = user.FirstName != personalInfo.FirstName || user.LastName != personalInfo.LastName;

				_logger.LogInformation("Change detection: emailChanged={EmailChanged}, phoneChanged={PhoneChanged}, nameChanged={NameChanged}", 
					emailChanged, phoneChanged, nameChanged);

				user.FirstName = personalInfo.FirstName;
				user.LastName = personalInfo.LastName;
				user.Email = personalInfo.Email;
				user.PhoneNumber = personalInfo.PhoneNumber;
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
				if (personalInfo.NewAvatar != null && personalInfo.NewAvatar.Length > 0)
				{
					// TODO: Implement file upload to storage
					// For now, just log the upload attempt
					_logger.LogInformation($"Avatar upload attempted for user {user.Id}");
				}

				_logger.LogInformation("Attempting to update user {UserId} with new data: FirstName='{FirstName}', LastName='{LastName}', Email='{Email}'", 
					user.Id, user.FirstName, user.LastName, user.Email);

				var result = await _userManager.UpdateAsync(user);
				if (result.Succeeded)
				{
					_logger.LogInformation("User {UserId} updated successfully", user.Id);
					TempData["SuccessMessage"] = "Personal information updated successfully.";
					
					if (emailChanged)
					{
						TempData["InfoMessage"] = "Please verify your new email address.";
						// TODO: Send email confirmation
					}
					
					if (phoneChanged)
					{
						TempData["InfoMessage"] = "Please verify your new phone number.";
					}
				}
				else
				{
					_logger.LogError("Failed to update user {UserId}. Errors: {Errors}", 
						user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
					
					foreach (var error in result.Errors)
					{
						ModelState.AddModelError("", error.Description);
					}
					TempData["ErrorMessage"] = "Failed to update personal information.";
				}
			}
			else
			{
				_logger.LogWarning("ModelState is invalid for user {UserId}. Errors: {Errors}", 
					user.Id, string.Join(", ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
				TempData["ErrorMessage"] = "Please correct the validation errors.";
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
		public async Task<IActionResult> DeleteAccount()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			// Get user's data summary
			var orderCount = await _context.Orders.CountAsync(o => o.UserId == user.Id);
			var bookCount = await _context.Books.CountAsync(b => b.AuthorId == user.Id);
			var hasPassword = await _userManager.HasPasswordAsync(user);

			var model = new DeleteAccountViewModel
			{
				FullName = user.FullName,
				Email = user.Email ?? "",
				UserName = user.UserName ?? "",
				CreatedAt = user.CreatedAt,
				TotalOrders = orderCount,
				BooksAuthored = bookCount,
				HasPassword = hasPassword
			};

			return View(model);
		}

		// POST: Deactivate Account
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> DeactivateAccount()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			try
			{
				// Set lockout end to far future (effectively deactivating)
				var lockoutEnd = DateTimeOffset.UtcNow.AddYears(100);
				var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);

				if (result.Succeeded)
				{
					_logger.LogInformation("User {UserId} deactivated their account", user.Id);
					
					// Sign out the user
					await _signInManager.SignOutAsync();
					
					TempData["SuccessMessage"] = "Your account has been deactivated. You can reactivate it by signing in again.";
					return RedirectToAction("Login");
				}
				else
				{
					_logger.LogError("Failed to deactivate account for user {UserId}. Errors: {Errors}", 
						user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
					TempData["ErrorMessage"] = "Failed to deactivate account. Please try again.";
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error deactivating account for user {UserId}", user.Id);
				TempData["ErrorMessage"] = "An error occurred while deactivating your account. Please try again.";
			}

			return RedirectToAction("ManageProfile", new { tab = "data-privacy" });
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

		// POST: Confirm Delete Account (handles the detailed deletion form)
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ConfirmDeleteAccount(DeleteAccountViewModel model)
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			// Check if user has external logins only (no password)
			var hasPassword = await _userManager.HasPasswordAsync(user);
			var externalLogins = await _userManager.GetLoginsAsync(user);

			if (!ModelState.IsValid)
			{
				// Repopulate model data
				var orderCount = await _context.Orders.CountAsync(o => o.UserId == user.Id);
				var bookCount = await _context.Books.CountAsync(b => b.AuthorId == user.Id);
				
				model.FullName = user.FullName;
				model.Email = user.Email ?? "";
				model.UserName = user.UserName ?? "";
				model.CreatedAt = user.CreatedAt;
				model.TotalOrders = orderCount;
				model.BooksAuthored = bookCount;
				
				return View("DeleteAccount", model);
			}

			// Verify password only if user has a password
			if (hasPassword)
			{
				var passwordCheck = await _userManager.CheckPasswordAsync(user, model.Password);
				if (!passwordCheck)
				{
					ModelState.AddModelError("Password", "Incorrect password.");
					// Repopulate model data
					var orderCount = await _context.Orders.CountAsync(o => o.UserId == user.Id);
					var bookCount = await _context.Books.CountAsync(b => b.AuthorId == user.Id);
					
					model.FullName = user.FullName;
					model.Email = user.Email ?? "";
					model.UserName = user.UserName ?? "";
					model.CreatedAt = user.CreatedAt;
					model.TotalOrders = orderCount;
					model.BooksAuthored = bookCount;
					model.HasPassword = hasPassword;
					
					return View("DeleteAccount", model);
				}
			}

			// Verify confirmation text
			if (model.ConfirmationText.Trim().ToUpper() != "DELETE MY ACCOUNT")
			{
				ModelState.AddModelError("ConfirmationText", "Please type 'DELETE MY ACCOUNT' exactly as shown.");
				// Repopulate model data
				var orderCount = await _context.Orders.CountAsync(o => o.UserId == user.Id);
				var bookCount = await _context.Books.CountAsync(b => b.AuthorId == user.Id);
				
				model.FullName = user.FullName;
				model.Email = user.Email ?? "";
				model.UserName = user.UserName ?? "";
				model.CreatedAt = user.CreatedAt;
				model.TotalOrders = orderCount;
				model.BooksAuthored = bookCount;
				model.HasPassword = hasPassword;
				
				return View("DeleteAccount", model);
			}

			try
			{
				using var transaction = await _context.Database.BeginTransactionAsync();

				// Delete related data
				var orders = await _context.Orders.Where(o => o.UserId == user.Id).ToListAsync();
				foreach (var order in orders)
				{
					_context.OrderItems.RemoveRange(order.OrderItems);
					_context.Orders.Remove(order);
				}

				var books = await _context.Books.Where(b => b.AuthorId == user.Id).ToListAsync();
				_context.Books.RemoveRange(books);

				await _context.SaveChangesAsync();

				// Delete user account
				var result = await _userManager.DeleteAsync(user);
				if (result.Succeeded)
				{
					await transaction.CommitAsync();
					_logger.LogInformation("User {UserId} ({Email}) deleted their account. Had password: {HasPassword}, External logins: {ExternalLogins}", 
						user.Id, user.Email, hasPassword, string.Join(", ", externalLogins.Select(l => l.LoginProvider)));
					
					// Sign out
					await _signInManager.SignOutAsync();
					
					TempData["SuccessMessage"] = "Your account has been permanently deleted. We're sorry to see you go.";
					return RedirectToAction("Index", "Home");
				}
				else
				{
					await transaction.RollbackAsync();
					_logger.LogError("Failed to delete account for user {UserId}. Errors: {Errors}", 
						user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
					ModelState.AddModelError("", "Failed to delete account. Please try again or contact support.");
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error deleting account for user {UserId}", user.Id);
				ModelState.AddModelError("", "An error occurred while deleting your account. Please try again.");
			}

			// Repopulate model data on error
			var finalOrderCount = await _context.Orders.CountAsync(o => o.UserId == user.Id);
			var finalBookCount = await _context.Books.CountAsync(b => b.AuthorId == user.Id);
			var finalHasPassword = await _userManager.HasPasswordAsync(user);
			
			model.FullName = user.FullName;
			model.Email = user.Email ?? "";
			model.UserName = user.UserName ?? "";
			model.CreatedAt = user.CreatedAt;
			model.TotalOrders = finalOrderCount;
			model.BooksAuthored = finalBookCount;
			model.HasPassword = finalHasPassword;
			
			return View("DeleteAccount", model);
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

		private async Task<string> GenerateUniqueUsernameAsync(string? email, string? name)
		{
			var suggestions = new List<string>();
			
			// Try to extract username from email
			if (!string.IsNullOrEmpty(email))
			{
				var emailPart = email.Split('@')[0];
				suggestions.Add(emailPart);
			}
			
			// Try to create username from name
			if (!string.IsNullOrEmpty(name))
			{
				var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
				if (nameParts.Length >= 2)
				{
					// FirstnameLastname format
					suggestions.Add($"{nameParts[0].ToLower()}{nameParts[1].ToLower()}");
					// FirstnameL format
					suggestions.Add($"{nameParts[0].ToLower()}{nameParts[1][0].ToString().ToLower()}");
				}
				else if (nameParts.Length == 1)
				{
					suggestions.Add(nameParts[0].ToLower());
				}
			}
			
			// Clean suggestions (remove special characters, ensure valid format)
			var cleanSuggestions = suggestions
				.Select(s => System.Text.RegularExpressions.Regex.Replace(s, @"[^a-zA-Z0-9_]", ""))
				.Where(s => s.Length >= 3 && s.Length <= 50)
				.Distinct()
				.ToList();
			
			// Find first available username
			foreach (var suggestion in cleanSuggestions)
			{
				if (await IsUsernameAvailableAsync(suggestion))
				{
					return suggestion;
				}
				
				// Try with numbers if base suggestion is taken
				for (int i = 1; i <= 99; i++)
				{
					var numberedSuggestion = $"{suggestion}{i}";
					if (await IsUsernameAvailableAsync(numberedSuggestion))
					{
						return numberedSuggestion;
					}
				}
			}
			
			// Fallback: generate random username
			return await GenerateRandomUsernameAsync();
		}

		// GET: SetPassword
		[Authorize]
		[HttpGet]
		public async Task<IActionResult> SetPassword()
		{
			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var hasPassword = await _userManager.HasPasswordAsync(user);
			if (hasPassword)
			{
				// User already has a password, redirect to change password
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			return View(new SetPasswordViewModel());
		}

		// POST: SetPassword
		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			var user = await _userManager.GetUserAsync(User);
			if (user == null) return RedirectToAction("Login");

			var hasPassword = await _userManager.HasPasswordAsync(user);
			if (hasPassword)
			{
				TempData["ErrorMessage"] = "User already has a password set.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			var result = await _userManager.AddPasswordAsync(user, model.NewPassword);
			if (result.Succeeded)
			{
				TempData["SuccessMessage"] = "Password has been set successfully.";
				return RedirectToAction("ManageProfile", new { tab = "security" });
			}

			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}

			return View(model);
		}

		// Private helper methods
		private async Task<bool> IsUsernameAvailableAsync(string username)
		{
			var existingUser = await _userManager.FindByNameAsync(username);
			return existingUser == null;
		}

		private async Task<string> GenerateRandomUsernameAsync()
		{
			var random = new Random();
			string username;
			
			do
			{
				username = $"user{random.Next(10000, 99999)}";
			} 
			while (!await IsUsernameAvailableAsync(username));
			
			return username;
		}
	}
}

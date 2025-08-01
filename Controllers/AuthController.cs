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

namespace BulkyBooksWeb.Controllers
{
	public class AuthController : Controller
	{
		private readonly ApplicationDbContext _context;
		private readonly IAuthorizationService _authService;
		private readonly IUserContext _userContext;
		private readonly UserService _userService;
		private readonly ILogger<AuthController> _logger;

		public AuthController(
			ApplicationDbContext context,
			IAuthorizationService authorizationService,
			IUserContext userContext, ILogger<AuthController> logger,
			UserService userService)
		{
			_context = context;
			_authService = authorizationService;
			_userContext = userContext;
			_userService = userService;
			_logger = logger;
		}


		public async Task<IActionResult> Profile()
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login");

			var user = await _userService.GetUserById((int)userId);
			if (user == null) return NotFound();
			UserProfileViewModel userProfileViewModel = new()
			{
				User = user,
				UpdateProfile = new UpdateProfileViewModel
				{
					FullName = user.FullName,
					Email = user.Email
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
				var user = await _context.Users
					.FirstOrDefaultAsync(u => u.Username == login.Username);

				if (user == null || !VerifyPassword(login.Password, user.PasswordHash))
				{
					ModelState.AddModelError(string.Empty, "Invalid credentials.");
					return View(login);
				}


				// Create claims for the authenticated user
				var claims = new List<Claim>
				{
					new(ClaimTypes.Name, user.Username),
					new(ClaimTypes.Role, user.Role.ToString().ToLowerInvariant()),
					new(ClaimTypes.NameIdentifier, user.Id.ToString())
				};

				var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

				// Sign in the user
				await HttpContext.SignInAsync(
					CookieAuthenticationDefaults.AuthenticationScheme,
					new ClaimsPrincipal(claimsIdentity),
					new AuthenticationProperties
					{
						IsPersistent = login.RememberMe,
						ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
					});

				Console.WriteLine("User logged in: " + user.Username);
				// Redirect to the return URL or home page
				returnUrl ??= login.ReturnUrl;
				return LocalRedirect(returnUrl ?? "/");

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

			if (await _context.Users.AnyAsync(u => u.Username == signUp.Username))
				errors.Add("Username already exists.");

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

			// Hash the password
			var passwordHash = HashPassword(signUp.Password);

			var adminCount = await _context.Users.CountAsync(u => u.Role == RoleOpt.Admin);
			var newUser = new User
			{
				Username = signUp.Username,
				PasswordHash = passwordHash,
				Role = adminCount > 0 ? signUp.Role : RoleOpt.Admin,
				Email = signUp.Email,
				FullName = signUp.FullName

			};

			_context.Users.Add(newUser);
			await _context.SaveChangesAsync();

			return RedirectToAction("Login");

		}

		[Authorize]
		[HttpPost]
		public async Task<IActionResult> Logout()
		{
			await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			return RedirectToAction("Index", "Home");
		}

		public IActionResult IsUsernameUnique(string username)
		{
			var isUnique = !_context.Users.Any(u => u.Username == username);
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
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login");

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
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdateProfile = model,
					User = await _userService.GetUserById((int)userId) ?? new()
				};
				return View("Profile", userProfileViewModel);
			}


			var user = await _userService.GetUserById((int)userId);
			if (user == null) return NotFound();

			user.FullName = model.FullName;
			user.Email = model.Email;

			await _context.SaveChangesAsync();

			return RedirectToAction("Profile");
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login");
			if (!ModelState.IsValid)
			{

				var userProfileViewModel = new UserProfileViewModel
				{
					ChangePassword = model,
					User = await _userService.GetUserById((int)userId) ?? new()
				};
				return View("Profile", userProfileViewModel);
			}


			var user = await _userService.GetUserById((int)userId);
			if (user == null) return NotFound();

			if (!VerifyPassword(model.CurrentPassword, user.PasswordHash))
			{
				ModelState.AddModelError(string.Empty, "Current password is incorrect.");
				return View("Profile", new UserProfileViewModel
				{
					ChangePassword = model,
					User = user
				});
			}

			user.PasswordHash = HashPassword(model.NewPassword);
			await _context.SaveChangesAsync();

			return RedirectToAction("Logout");
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> UpdatePreferences(UpdatePreferencesViewModel model)
		{

			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login");

			if (!ModelState.IsValid)
			{
				var userProfileViewModel = new UserProfileViewModel
				{
					UpdatePreferences = model,
					User = await _userService.GetUserById((int)userId) ?? new()
				};
				return View("Profile", userProfileViewModel);
			}

			var user = await _userService.GetUserById((int)userId);
			if (user == null) return NotFound();

			// user.EmailNotificationEnabled = model.EmailNotificationEnabled;
			// user.ActivityAlertEnabled = model.ActivityAlertEnabled;
			// user.ItemsPerPage = model.ItemsPerPage;

			// await _context.SaveChangesAsync();

			return RedirectToAction("Profile");
		}

		private static string HashPassword(string password)
		{
			byte[] salt = new byte[16];
			using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
			{
				rng.GetBytes(salt);
			}

			// Hash the password using PBKDF2
			byte[] hash = KeyDerivation.Pbkdf2(
				password: password,
				salt: salt,
				prf: KeyDerivationPrf.HMACSHA256,
				iterationCount: 10000,
				numBytesRequested: 256 / 8);

			// Combine salt and hash (store as base64)
			return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
		}

		private static bool VerifyPassword(string enteredPassword, string storedPasswordHash)
		{
			// Split the stored hash to get salt and password hash
			var parts = storedPasswordHash.Split(':');
			if (parts.Length != 2) return false;

			byte[] salt = Convert.FromBase64String(parts[0]);
			byte[] storedHash = Convert.FromBase64String(parts[1]);

			// Hash the entered password with the stored salt
			byte[] enteredHash = KeyDerivation.Pbkdf2(
				password: enteredPassword,
				salt: salt,
				prf: KeyDerivationPrf.HMACSHA256,
				iterationCount: 10000,
				numBytesRequested: 256 / 8);

			// Compare both hashes
			return storedHash.SequenceEqual(enteredHash);
		}
	}

}

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using BulkyBooksWeb.Data;
using System.Security.Claims;

namespace BulkyBooksWeb.Controllers;

public class AuthController : Controller
{
	private readonly ApplicationDbContext _context;

	public AuthController(ApplicationDbContext context)
	{
		_context = context;
	}

	public IActionResult Login()
	{
		return View();
	}

	[HttpPost]
	public async Task<IActionResult> Login(LoginModel login)
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
			var returnUrl = login.ReturnUrl;
			if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}

			return RedirectToAction("Index", "Home");
		}

		return View(login);
	}

	public IActionResult SignUp()
	{
		return View();
	}

	[HttpPost]
	public async Task<IActionResult> SignUp(SignUpModel signUp)
	{
		if (ModelState.IsValid)
		{
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

		return View(signUp);
	}

	[HttpPost]
	public async Task<IActionResult> Logout()
	{
		await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
		return RedirectToAction("Index", "Home"); // Redirect to home page after logout
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
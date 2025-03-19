using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models.ViewModels;
using ChapaNET;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Extensions;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using BulkyBooksWeb.Policies;
using BulkyBooksWeb.Dtos;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

namespace BulkyBooksWeb.Controllers
{

	[Authorize(Roles = "admin, author, user")]
	[Route("[controller]")]
	public class CheckoutController : Controller
	{
		private readonly Chapa _chapa;
		private readonly ApplicationDbContext _context;
		private readonly OrderService _orderService;
		private readonly IAuthorizationService _authorizationService;
		private readonly ILogger<CheckoutController> _logger;
		private readonly IConfiguration _configuration;
		private readonly IUserContext _userContext;


		public CheckoutController(
			Chapa chapa, ApplicationDbContext context,
			OrderService orderService, ILogger<CheckoutController> logger,
			IAuthorizationService authorizationService, IConfiguration configuration,
			IUserContext userContext)
		{
			_chapa = chapa;
			_context = context;
			_orderService = orderService;
			_logger = logger;
			_configuration = configuration;
			_authorizationService = authorizationService;
			_userContext = userContext;
		}

		[HttpGet]
		public IActionResult Index()
		{
			var cart = HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? new List<CartItemDTO>();
			var model = new CheckoutViewModel
			{
				CartItems = GetCartItemDTOs(cart),
				TaxAmount = CalculateTax(cart)
			};

			model.Subtotal = model.CartItems.Sum(i => i.Price * i.Quantity);
			model.OrderTotal = model.Subtotal + model.TaxAmount;

			return View(model);
		}

		[HttpGet]
		[Route("PaymentFailed")]
		public IActionResult PaymentFailed()
		{
			return View("PaymentFailed");
		}

		[HttpGet]
		[Route("OrderConfirmation")]
		public async Task<IActionResult> OrderConfirmation()
		{
			try
			{
				var orderId = TempData["OrderId"] as int?;
				if (orderId == null)
				{
					_logger.LogWarning("Order ID not found in TempData.");
					ModelState.AddModelError("", "Order ID not found.");
					return RedirectToAction("Index");
				}

				var orderDto = await _orderService.GetOrderConfirmationDtoAsync(orderId.Value);
				if (orderDto == null) return NotFound();
				var authResult = await _authorizationService.AuthorizeAsync(User, orderDto.UserId, new OrderOwnerOrAdminRequirement());
				if (!authResult.Succeeded)
				{
					_logger.LogWarning("User {UserId} is not authorized to view order {OrderId}", User.FindFirstValue(ClaimTypes.NameIdentifier), orderId);
					return Forbid();
				}

				return View(orderDto);
			}
			catch (Exception ex)
			{
				return NotFound(ex.Message);
			}
		}

		[HttpGet]
		[AllowAnonymous]
		[Route("PaymentSuccess")]
		public IActionResult PaymentSuccess([FromQuery] string token)
		{
			if (!ValidateToken(token, out int orderId, out var userId))
			{
				_logger.LogError("Invalid token: {Token}", token);
				return BadRequest("Invalid token.");
			}
			if (userId == null)
			{
				_logger.LogWarning("User ID not found in token.");
				return BadRequest("User ID not found in token.");
			}

			// Store the orderId in TempData for the next request
			TempData["OrderId"] = orderId;

			return RedirectToAction("OrderConfirmation");
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ProcessCheckout(CheckoutViewModel model)
		{
			Console.WriteLine("Processing checkout...");

			var cart = GetCartItemDTOs(HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? []);
			model.CartItems = cart;
			model.Subtotal = model.CartItems.Sum(i => i.Price * i.Quantity);
			model.TaxAmount = CalculateTax(cart);
			model.OrderTotal = model.Subtotal + model.TaxAmount;

			if (!ModelState.IsValid)
			{
				var errors = ModelState
					.Where(x => x.Value?.Errors.Count > 0)
					.Select(x => new { x.Key, x.Value?.Errors })
					.ToList();

				_logger.LogError("Validation errors: {@Errors}", errors);
				return View("Index", model);
			}

			try
			{
				var txRef = Chapa.GetUniqueRef();
				var userId = _userContext.GetCurrentUserId();
				if (userId == null)
				{
					_logger.LogWarning("User not found while creating order.");
					return RedirectToAction("Login", "Auth");
				}

				var order = await _orderService.CreateTempOrderFromCartAsync(
							cart,
							txRef,
							model.OrderTotal);

				var callbackUrl = _configuration["PaymentGateway:CallbackUrl"];
				var token = GenerateToken(order.Id, userId.Value);
				var returnUrl = $"{_configuration["PaymentGateway:ReturnRootUrl"]}?token={token}";

				// Create Chapa transaction request
				var request = new ChapaRequest(
					amount: (double)model.OrderTotal,
					email: model.Email,
					firstName: model.FirstName,
					lastName: model.LastName,
					tx_ref: txRef,
					currency: model.Currency,
					callback_url: callbackUrl,
					return_url: returnUrl,
					phoneNo: model.PhoneNumber,
					customTitle: $"Bulky Books - Order #{txRef}"
				);

				var response = await _chapa.RequestAsync(request);
				if (response.Status?.ToLower() == "success")
				{
					// Store transaction reference in session
					HttpContext.Session.SetString("ChapaTxRef", request.TransactionReference);
					if (response.CheckoutUrl != null)
					{
						return Redirect(response.CheckoutUrl);
					}
					return RedirectToAction("PaymentError");
				}

				await _orderService.FailOrderAsync(order.Id);

				_logger.LogError("Chapa payment initialization failed: {Response}", response);
				ModelState.AddModelError("", "Payment initialization failed");
				return View("Index", model);
			}
			catch
			{
				ModelState.AddModelError("", "An error occurred while processing your payment. Please try again.");
				return View("Index", model);
			}
		}

		[HttpGet]
		[AllowAnonymous]
		[Route("VerifyPayment")]
		public async Task<IActionResult> VerifyPayment([FromQuery] TrxResponseDto trxRes)
		{
			if (trxRes == null)
			{
				_logger.LogError("Invalid JSON response from Chapa.");
				return BadRequest("Invalid JSON response.");
			}

			_logger.LogInformation("Verifying payment with response: {JsonResponse}", trxRes.ref_id);

			try
			{
				var tx_ref = trxRes.ref_id;
				var isValid = await _chapa.VerifyAsync(tx_ref);

				if (isValid == null || !isValid.IsSuccess)
				{
					await _orderService.UpdateOrderPaymentStatusAsync(tx_ref, OrderStatus.Failed);
					_logger.LogError("Payment verification failed: {TransactionReference}", tx_ref);
					return BadRequest("Payment verification failed.");
				}

				_logger.LogInformation("Payment verified successfully: {TransactionReference}", tx_ref);

				var order = await _orderService.UpdateOrderPaymentStatusAsync(tx_ref, OrderStatus.Completed);

				// Clear the cart after successful order creation
				HttpContext.Session.Remove("Cart");

				return Ok("Payment verified successfully.");
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Payment verification failed.");
				return StatusCode(500, "An error occurred while verifying the payment.");
			}
		}

		private List<CartItemDTO> GetCartItemDTOs(List<CartItemDTO> cartItems)
		{
			var bookIds = cartItems.Select(i => i.BookId).ToList();
			var books = _context.Books.Where(b => bookIds.Contains(b.Id)).ToList();

			return cartItems.Select(item => new CartItemDTO
			{
				BookId = item.BookId,
				Title = books.FirstOrDefault(b => b.Id == item.BookId)?.Title ?? "Unknown Book",
				Price = item.Price,
				Quantity = item.Quantity
			}).ToList();
		}

		private static decimal CalculateTax(List<CartItemDTO> cart)
		{
			return cart.Sum(i => i.Price * i.Quantity) * 0.15m; // 15% tax
		}

		private string GenerateToken(int orderId, int userId)
		{
			var jwtConfig = _configuration.GetSection("JwtConfig");
			if (string.IsNullOrEmpty(jwtConfig["Key"]) || string.IsNullOrEmpty(jwtConfig["Issuer"]) || string.IsNullOrEmpty(jwtConfig["Audience"]))
			{
				throw new Exception("JWT configuration is missing required values.");
			}

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Key"] ?? ""));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

			var claims = new[]
			{
				new Claim("orderId", orderId.ToString()),
				new Claim("userId", userId.ToString()),
				new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
				new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(jwtConfig.GetValue<int>("DurationInMinutes")).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
			};

			var token = new JwtSecurityToken(
				issuer: jwtConfig["Issuer"],
				audience: jwtConfig["Audience"],
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(jwtConfig.GetValue<int>("DurationInMinutes")),
				signingCredentials: credentials
			);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}

		private bool ValidateToken(string token, out int orderId, out int? userId)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var jwtConfig = _configuration.GetSection("JwtConfig");
			if (string.IsNullOrEmpty(jwtConfig["Key"]) || string.IsNullOrEmpty(jwtConfig["Issuer"]) || string.IsNullOrEmpty(jwtConfig["Audience"]))
			{
				throw new Exception("JWT configuration is missing required values.");
			}

			var validationParameters = new TokenValidationParameters
			{
				ValidateIssuer = true,
				ValidIssuer = jwtConfig["Issuer"],
				ValidateAudience = true,
				ValidAudience = jwtConfig["Audience"],
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Key"] ?? "")),
				ValidateLifetime = true
			};

			try
			{
				var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
				var orderClaim = claimsPrincipal.FindFirst("orderId")?.Value;
				var userClaim = claimsPrincipal.FindFirst("userId")?.Value;
				if (orderClaim == null || userClaim == null)
				{
					orderId = 0;
					userId = null;
					return false;
				}
				orderId = int.Parse(orderClaim);
				userId = int.Parse(userClaim);
				return true;
			}
			catch
			{
				orderId = 0;
				userId = null;
				return false;
			}
		}
	}
}
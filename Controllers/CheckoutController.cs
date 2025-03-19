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

		public CheckoutController(
			Chapa chapa, ApplicationDbContext context,
			OrderService orderService, ILogger<CheckoutController> logger,
			IAuthorizationService authorizationService)
		{
			_chapa = chapa;
			_context = context;
			_orderService = orderService;
			_logger = logger;
			_authorizationService = authorizationService;
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
		[Route("OrderConfirmation/{id}")]
		public async Task<IActionResult> OrderConfirmation(int id)
		{
			try
			{
				var orderDto = await _orderService.GetOrderConfirmationDtoAsync(id);
				if (orderDto == null) return NotFound();
				var authResult = await _authorizationService.AuthorizeAsync(User, orderDto.UserId, new OrderOwnerOrAdminRequirement());
				if (!authResult.Succeeded)
				{
					_logger.LogWarning("User {UserId} is not authorized to view order {OrderId}", User.FindFirstValue(ClaimTypes.NameIdentifier), id);
					return Forbid();
				}

				return View(orderDto);
			}
			catch (Exception ex)
			{
				return NotFound(ex.Message);
			}
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
			Console.WriteLine(model.OrderTotal);

			try
			{
				// Create Chapa transaction request
				var txRef = Chapa.GetUniqueRef();
				var request = new ChapaRequest(
					amount: (double)model.OrderTotal,
					email: model.Email,
					firstName: model.FirstName,
					lastName: model.LastName,
					tx_ref: GenerateTransactionReference(),
					currency: model.Currency,
					callback_url: model.CallbackURL,
					// return_url: model.ReturnURL,
					phoneNo: model.PhoneNumber,
					customTitle: $"Bulky Books - Order #{txRef}"
				);

				var response = await _chapa.RequestAsync(request);
				if (response.Status == "success")
				{
					// Store transaction reference in session
					HttpContext.Session.SetString("ChapaTxRef", request.TransactionReference);
					if (response.CheckoutUrl != null)
						return Redirect(response.CheckoutUrl);
					return RedirectToAction("PaymentError");
				}

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
		[Route("VerifyPayment")]
		public async Task<IActionResult> VerifyPayment([FromBody] TrxResponseDto trxRes)
		{
			if (trxRes == null)
			{
				_logger.LogError("Invalid JSON response from Chapa");
				return RedirectToAction("PaymentFailed");
			}
			_logger.LogInformation("Verifying payment with response: {JsonResponse}", trxRes.ToString());
			try
			{
				var tx_ref = trxRes.ref_id;
				var isValid = await _chapa.VerifyAsync(tx_ref);
				if (isValid == null || !isValid.IsSuccess)
					return RedirectToAction("PaymentFailed");

				var cart = HttpContext.Session.Get<List<CartItemDTO>>("Cart") ?? [];

				var order = await _orderService.CreateOrderFromCartAsync(
					cart,
					tx_ref,
					(decimal)isValid.data.amount
				);

				// Clear cart after successful order creation
				HttpContext.Session.Remove("Cart");

				return RedirectToAction("OrderConfirmation", new { id = order.Id });
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Payment verification failed");
				return RedirectToAction("PaymentFailed");
			}
		}
		private static string GenerateTransactionReference()
		{
			return $"TX-{Guid.NewGuid().ToString()[..8]}";
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
	}
}
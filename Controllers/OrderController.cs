using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Controllers
{
	public class OrderController : Controller
	{
		private readonly ILogger<OrderController> _logger;
		private readonly OrderService _orderService;
		private readonly IUserContext _userContext;
		public OrderController(
			ILogger<OrderController> logger,
			OrderService orderService,
			IUserContext userContext)
		{
			_userContext = userContext;
			_logger = logger;
			_orderService = orderService;
		}

		public async Task<IActionResult> Index()
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return NotFound("User not found");

			var orders = await _orderService.GetOrdersByUserIdAsync((int)userId);
			return View(orders);
		}

		public async Task<IActionResult> Details(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var userId = _userContext.GetCurrentUserId();
			if (userId == null || order.UserId != userId) return Forbid("You do not have permission to view this order.");

			return View(order);
		}

		public async Task<IActionResult> History([FromQuery] string dateRange, [FromQuery] string status)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login", "Auth");

			var orders = await _orderService.GetOrdersByUserIdAsync((int)userId);

			// filtering teh orders
			if (int.TryParse(dateRange, out int dateRangeInt) && dateRangeInt > 0)
			{
				orders = [.. orders.Where(o => o.OrderDate >= DateTime.Now.AddDays(-dateRangeInt))];
			}
			if (!string.IsNullOrEmpty(status) && !status.Equals("all", StringComparison.CurrentCultureIgnoreCase))
			{
				orders = [.. orders.Where(o => o.Status.ToString().Equals(status, StringComparison.OrdinalIgnoreCase))];
			}

			return View(orders);
		}

		[HttpPost("CancelOrder/{orderId}")]
		public async Task<IActionResult> CancelOrder(int orderId)
		{
			var order = await _orderService.GetOrderByIdAsync(orderId);
			if (order == null) return NotFound("Order not found");

			var userId = _userContext.GetCurrentUserId();
			if (userId == null || order.UserId != userId) return Forbid("You do not have permission to cancel this order.");

			if (order.Status != OrderStatus.Pending) return BadRequest("Only pending orders can be cancelled.");

			order.Status = OrderStatus.Cancelled;
			await _orderService.UpdateOrderAsync(order);
			return RedirectToAction("Index");
		}

	}
}
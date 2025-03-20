using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using BulkyBooksWeb.Policies;

namespace BulkyBooksWeb.Controllers
{
	[Authorize(Roles = "admin, author, user")]
	public class OrderController : Controller
	{
		private readonly ILogger<OrderController> _logger;
		private readonly OrderService _orderService;
		private readonly IUserContext _userContext;
		private readonly IAuthorizationService _authorizationService;

		public OrderController(
			ILogger<OrderController> logger,
			OrderService orderService,
			IUserContext userContext,
			IAuthorizationService authorizationService)
		{
			_userContext = userContext;
			_logger = logger;
			_orderService = orderService;
			_authorizationService = authorizationService;
		}

		[Authorize(Roles = "admin")]
		public async Task<IActionResult> Index([FromQuery] OrderFilterViewModel orderFilter)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login", "Auth", new { returnUrl = Url.Action("Index") });


			var orders = await _orderService.GetAllOrders();
			// filter
			if (orderFilter.OrderId > 0)
				orders = [.. orders.Where(o => o.Id == orderFilter.OrderId)];
			if (!string.IsNullOrEmpty(orderFilter.CustomerName))
				orders = [.. orders.Where(o => o.User.Username.Contains(orderFilter.CustomerName, StringComparison.CurrentCultureIgnoreCase))];
			if (orderFilter.DateFrom != DateOnly.FromDateTime(DateTime.MinValue) && orderFilter.DateTo != DateOnly.FromDateTime(DateTime.MinValue))
				orders = [.. orders.Where(o => o.OrderDate >= orderFilter.DateFrom.ToDateTime(new TimeOnly(0, 0))
											&& o.OrderDate <= orderFilter.DateTo.ToDateTime(new TimeOnly(23, 59)))];

			orders = [.. orders.OrderByDescending(o => o.OrderDate)];
			OrderManagementViewModel orderManagmentViewModel = new()
			{
				Orders = orders,
				TotalOrdersMonthly = orders.Count(o => o.OrderDate.Month == DateTime.Now.Month && o.OrderDate.Year == DateTime.Now.Year),
				MonthlyRevenue = orders.Where(o => o.OrderDate.Month == DateTime.Now.Month && o.OrderDate.Year == DateTime.Now.Year).Sum(o => o.OrderTotal),
				PendingOrders = orders.Count(o => o.Status == OrderStatus.Pending),
				CompletedOrders = orders.Count(o => o.Status == OrderStatus.Completed),
				RefundedOrders = orders.Count(o => o.Status == OrderStatus.Refunded),
				CancelledOrders = orders.Count(o => o.Status == OrderStatus.Cancelled)
			};

			return View(orderManagmentViewModel);
		}

		public async Task<IActionResult> Detail(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var isAuth = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isAuth.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning(" User {userId} is not authorized to view otder {OrderId}", userId, order.Id);
				return Forbid();
			}

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

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to cancel order {OrderId}", userId, orderId);
				return Forbid();
			}

			try
			{
				await _orderService.CancelOrderAsync(orderId);
				_logger.LogInformation("Order {OrderId} cancel successfully", orderId);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to cancel order {OrderId}", orderId);
				return BadRequest("Failed to cancel order. Please try again later.");
			}
		}

		[HttpPost("RefundOrder/{orderId}")]
		public async Task<IActionResult> RefundOrder(int orderId)
		{
			var order = await _orderService.GetOrderByIdAsync(orderId);
			if (order == null) return NotFound("Order not found");

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to refund order {OrderId}", userId, orderId);
				return Forbid();
			}

			try
			{
				await _orderService.RefundOrderAsync(orderId);
				_logger.LogInformation("Order {OrderId} Refunded successfully", orderId);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to Refund order {OrderId}", orderId);
				return BadRequest("Failed to Refund order. Please try again later.");
			}
		}

		[HttpPost("CompleteOrder/{orderId}")]
		public async Task<IActionResult> CompleteOrder(int orderId)
		{
			var order = await _orderService.GetOrderByIdAsync(orderId);
			if (order == null) return NotFound("Order not found");

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to complete order {OrderId}", userId, orderId);
				return Forbid();
			}

			try
			{
				await _orderService.CompleteOrderAsync(orderId);
				_logger.LogInformation("Order {OrderId} completed successfully", orderId);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to complete order {OrderId}", orderId);
				return BadRequest("Failed to complete order. Please try again later.");
			}
		}

	}
}
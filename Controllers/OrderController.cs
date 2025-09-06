using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using BulkyBooksWeb.Policies;

namespace BulkyBooksWeb.Controllers
{
	[Authorize(Roles = "Admin, Author, User")]
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

		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> Index([FromQuery] OrderFilterViewModel orderFilter)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login", "Auth", new { returnUrl = Url.Action("Index") });


			var orders = await _orderService.GetAllOrders();
			// filter
			if (orderFilter.OrderId > 0)
				orders = [.. orders.Where(o => o.Id == orderFilter.OrderId)];
			if (!string.IsNullOrEmpty(orderFilter.CustomerName))
				orders = [.. orders.Where(o => o.User?.UserName?.Contains(orderFilter.CustomerName, StringComparison.CurrentCultureIgnoreCase) == true)];
			if (orderFilter.DateFrom != DateOnly.FromDateTime(DateTime.MinValue) && orderFilter.DateTo != DateOnly.FromDateTime(DateTime.MinValue))
				orders = [.. orders.Where(o => o.OrderDate >= orderFilter.DateFrom.ToDateTime(new TimeOnly(0, 0))
											&& o.OrderDate <= orderFilter.DateTo.ToDateTime(new TimeOnly(23, 59)))];

			orders = [.. orders.OrderByDescending(o => o.OrderDate)];
			OrderManagementViewModel orderManagmentViewModel = new()
			{
				Orders = orders,
				TotalOrdersMonthly = orders.Count(o => o.OrderDate.Month == DateTime.Now.Month && o.OrderDate.Year == DateTime.Now.Year),
				MonthlyRevenue = orders.Where(o =>
											o.OrderDate.Month == DateTime.Now.Month &&
											o.OrderDate.Year == DateTime.Now.Year && o.Status == OrderStatus.Completed)
										.Sum(o => o.OrderTotal),
				TotalOrders = orders.Count(),
				TotalCompletedRevenue = orders.Where(o => o.Status == OrderStatus.Completed).Sum(o => o.OrderTotal),
				TotalRefundedRevenue = orders.Where(o => o.Status == OrderStatus.Refunded).Sum(o => o.OrderTotal),
				TotalItemsSold = orders.Sum(o => o.OrderItems.Sum(oi => oi.Quantity)),
				PendingRevenue = orders.Where(o => o.Status == OrderStatus.Pending).Sum(o => o.OrderTotal),
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

			var orders = await _orderService.GetOrdersByUserIdAsync(userId);

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

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> CancelOrder(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to cancel order {id}", userId, id);
				return Forbid();
			}

			try
			{
				await _orderService.CancelOrderAsync(id);
				_logger.LogInformation("Order {OrderId} cancel successfully", id);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to cancel order {OrderId}", id);
				return BadRequest("Failed to cancel order. Please try again later.");
			}
		}

		[HttpPost]
		[Authorize(Roles = "Admin")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> RefundOrder(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to refund order {id}", userId, id);
				return Forbid();
			}

			try
			{
				await _orderService.RefundOrderAsync(id);
				_logger.LogInformation("Order {id} Refunded successfully", id);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to Refund order {id}", id);
				return BadRequest("Failed to Refund order. Please try again later.");
			}
		}

		[HttpPost]
		[Authorize(Roles = "Admin")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> CompleteOrder(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var isValid = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isValid.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to complete order {OrderId}", userId, id);
				return Forbid();
			}

			try
			{
				await _orderService.CompleteOrderAsync(id);
				_logger.LogInformation("Order {id} completed successfully", id);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to complete order {id}", id);
				return BadRequest("Failed to complete order. Please try again later.");
			}
		}

		[HttpPost]
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> UpdateOrderNotes([FromForm] int Id, [FromForm] string Note)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login", "Auth", new { returnUrl = Url.Action("Index") });

			var order = await _orderService.GetOrderByIdAsync(Id);
			if (order == null) return NotFound("Order not found");

			order.Note = Note;
			try
			{
				await _orderService.UpdateOrderAsync(order);
				TempData["Success"] = "Order updated successfully";
				_logger.LogInformation("Order {id} updated successfully", Id);
				return RedirectToAction("Index");
			}
			catch (Exception)
			{
				_logger.LogError("Failed to update order {id}", Id);
				TempData["Error"] = "Failed to update order. Please try again later.";
				return BadRequest("Failed to update order. Please try again later.");
			}
		}

		[HttpPost]
		[Authorize(Roles = "Admin")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> BulkAction([FromForm] string action, [FromForm] int[] orderIds)
		{
			var userId = _userContext.GetCurrentUserId();
			if (userId == null) return RedirectToAction("Login", "Auth", new { returnUrl = Url.Action("Index") });

			if (orderIds.Length == 0)
			{
				TempData["Error"] = "No orders selected";
				return RedirectToAction("Index");
			}

			try
			{
				switch (action.ToLower())
				{
					case "complete":
						foreach (var orderId in orderIds)
						{
							await _orderService.CompleteOrderAsync(orderId);
						}
						break;
					case "cancel":
						foreach (var orderId in orderIds)
						{
							await _orderService.CancelOrderAsync(orderId);
						}
						break;
					case "refund":
						foreach (var orderId in orderIds)
						{
							await _orderService.RefundOrderAsync(orderId);
						}
						break;
					default:
						TempData["Error"] = "Invalid action";
						return RedirectToAction("Index");
				}
				TempData["Success"] = $"{action} action completed successfully";
				return RedirectToAction("Index");
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Failed to perform bulk action {Action} on orders {OrderIds}", action, string.Join(", ", orderIds));
				TempData["Error"] = $"Failed to perform bulk action. Please try again later.";
				return RedirectToAction("Index");
			}
		}

		[HttpGet]
		[Authorize(Roles = "Admin, Author, User")]
		public async Task<IActionResult> Print(int id)
		{
			var order = await _orderService.GetOrderByIdAsync(id);
			if (order == null) return NotFound("Order not found");

			var isAuth = await _authorizationService.AuthorizeAsync(User, order.UserId, new OrderOwnerOrAdminRequirement());
			if (!isAuth.Succeeded)
			{
				var userId = _userContext.GetCurrentUserId();
				if (userId == null) return RedirectToAction("Login", "Auth");
				_logger.LogWarning("User {userId} is not authorized to print order {id}", userId, order.Id);
				return Forbid();
			}

			return View(order);
		}
	}
}
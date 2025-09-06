using System.Security.Claims;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Dtos;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Services
{
	public interface IOrderService
	{
		Task<Order> CreateTempOrderFromCartAsync(List<CartItemDTO> cartItems, string transactionReference, decimal amount);
		Task<Order> GetOrderByIdAsync(int id);
	}

	public class OrderService : IOrderService
	{
		private readonly ApplicationDbContext _context;
		private readonly ILogger<OrderService> _logger;
		private readonly IUserContext _userContext;

		public OrderService(
			ApplicationDbContext context,
			ILogger<OrderService> logger, IUserContext userContext)
		{
			_userContext = userContext;
			_context = context;
			_logger = logger;
		}

		public async Task<IEnumerable<Order>> GetAllOrders()
		{
			var orders = await _context.Orders
				.Include(o => o.OrderItems)
				.ToListAsync();

			return orders;
		}

		public async Task<IEnumerable<Order>> GetOrdersByUserIdAsync(string userId)
		{
			var orders = await _context.Orders
				.Include(o => o.OrderItems)
				.Where(o => o.UserId == userId)
				.ToListAsync();

			return orders;
		}

		public async Task<OrderConfirmationDto?> GetOrderConfirmationDtoAsync(int id)
		{
			var order = await _context.Orders
				.Include(o => o.OrderItems)
				.FirstOrDefaultAsync(o => o.Id == id);

			return order == null ? null : new OrderConfirmationDto
			{
				Id = order.Id,
				OrderDate = order.OrderDate,
				OrderTotal = order.OrderTotal,
				Status = order.Status,
				TransactionReference = order.TransactionReference,
				UserId = order.UserId,
				OwnerEmail = order.User?.Email ?? "",
				   OrderItems = order.OrderItems
					   .Join(_context.Books, oi => oi.BookId, b => b.Id, (oi, b) => new OrderItemDto
					   {
						   BookId = oi.BookId,
						   BookTitle = oi.BookTitle,
						   Price = oi.Price,
						   Quantity = oi.Quantity,
						   Author =  b.Author?.FullName ?? string.Empty,
						   PdfFilePath = b.PdfFilePath
					   })
					   .ToList()
			};
		}
		public async Task<Order> CreateTempOrderFromCartAsync(List<CartItemDTO> cartItems, string transactionReference, decimal amount)
		{
			var currentUser = _userContext.GetCurrentUserId();
			if (currentUser == null)
			{
				_logger.LogWarning("User not found while creating order.");
				throw new Exception("User not found.");
			}
			try
			{
				var order = new Order
				{
					UserId = currentUser,
					Status = OrderStatus.Pending,
					TransactionReference = transactionReference,
					OrderTotal = amount,
					OrderDate = DateTime.UtcNow,

					OrderItems = cartItems.Select(ci => new OrderItem
					{
						BookId = ci.BookId,
						BookTitle = ci.Title,
						Price = ci.Price,
						Quantity = ci.Quantity,
						OrderId = 0 // initialized to 0, will be set by EF Core
					}).ToList()
				};

				_context.Orders.Add(order);
				await _context.SaveChangesAsync();
				return order;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error creating order");
				throw; // Or handle specific exceptions
			}
		}

		public async Task<Order> UpdateOrderPaymentStatusAsync(string tx_ref, OrderStatus status)
		{
			var order = await _context.Orders.FirstOrDefaultAsync(o => o.TransactionReference == tx_ref) ?? throw new Exception("Order not found");
			order.Status = status;
			order.PaymentDate = DateTime.UtcNow;

			await _context.SaveChangesAsync();
			return order;
		}

		public async Task CompleteOrderAsync(int orderId)
		{
			var order = await _context.Orders.FindAsync(orderId) ?? throw new Exception("Order not found");
			if (order.Status != OrderStatus.Pending)
			{
				throw new Exception("Only pending orders can be completed.");
			}
			order.Status = OrderStatus.Completed;
			await _context.SaveChangesAsync();
		}

		public async Task CancelOrderAsync(int orderId)
		{
			var order = await _context.Orders.FindAsync(orderId) ?? throw new Exception("Order not found");
			if (order.Status != OrderStatus.Pending)
			{
				throw new Exception("Only pending orders can be cancelled.");
			}
			order.Status = OrderStatus.Cancelled;
			await _context.SaveChangesAsync();
		}

		public async Task RefundOrderAsync(int orderId)
		{
			var order = await _context.Orders.FindAsync(orderId) ?? throw new Exception("Order not found");
			if (order.Status != OrderStatus.Completed)
			{
				throw new Exception("Only completed orders can be refunded.");
			}
			order.Status = OrderStatus.Refunded;
			await _context.SaveChangesAsync();
		}

		public async Task FailOrderAsync(int orderId)
		{
			var order = await _context.Orders.FindAsync(orderId) ?? throw new Exception("Order not found");
			if (order.Status != OrderStatus.Pending)
			{
				throw new Exception("Only pending orders can be marked as failed.");
			}
			order.Status = OrderStatus.Failed;
			await _context.SaveChangesAsync();
		}

		public async Task<Order> GetOrderByIdAsync(int id)
		{
			var order = await _context.Orders
							.Include(o => o.OrderItems)
							.FirstOrDefaultAsync(o => o.Id == id)
							?? throw new Exception($"Order with id {id} not found.");
			return order;
		}

		public async Task UpdateOrderAsync(Order order)
		{
			try
			{
				_context.Orders.Update(order);
				await _context.SaveChangesAsync();
			}
			catch (DbUpdateConcurrencyException ex)
			{
				_logger.LogError(ex, "Error updating order with id {OrderId}", order.Id);
				throw;
			}
		}
	}
}
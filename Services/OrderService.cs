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
		Task<Order> CreateOrderFromCartAsync(List<CartItemDTO> cartItems, string transactionReference, decimal amount);
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
				OwnerEmail = order.User.Email,
				OrderItems = order.OrderItems.Select(oi => new OrderItemDto
				{
					BookId = oi.BookId,
					BookTitle = oi.BookTitle,
					Price = oi.Price,
					Quantity = oi.Quantity
				}).ToList()
			};
		}
		public async Task<Order> CreateOrderFromCartAsync(List<CartItemDTO> cartItems, string transactionReference, decimal amount)
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
					UserId = (int)currentUser,
					Status = OrderStatus.Completed,
					TransactionReference = transactionReference,
					OrderTotal = amount,
					PaymentDate = DateTime.UtcNow,

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

		public async Task<Order> GetOrderByIdAsync(int id)
		{
			var order = await _context.Orders
							.Include(o => o.OrderItems)
							.FirstOrDefaultAsync(o => o.Id == id)
							?? throw new Exception($"Order with id {id} not found.");
			return order;
		}
	}
}
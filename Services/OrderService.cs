using BulkyBooksWeb.Data;
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

		public OrderService(ApplicationDbContext context, ILogger<OrderService> logger)
		{
			_context = context;
			_logger = logger;
		}

		public async Task<Order> CreateOrderFromCartAsync(List<CartItemDTO> cartItems, string transactionReference, decimal amount)
		{
			try
			{
				var order = new Order
				{
					TransactionReference = transactionReference,
					OrderTotal = amount,
					Status = OrderStatus.Pending,
					PaymentDate = DateTime.UtcNow,

					OrderItems = cartItems.Select(ci => new OrderItem
					{
						BookId = ci.BookId,
						BookTitle = ci.Title, // Populate from cart or DB
						Price = ci.Price,
						Quantity = ci.Quantity
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
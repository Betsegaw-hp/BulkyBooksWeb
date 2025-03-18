namespace BulkyBooksWeb.Models.ViewModels
{
	public class OrderManagementViewModel
	{
		public IEnumerable<Order> Orders { get; set; } = [];
		public int TotalOrdersMonthly { get; set; }
		public decimal MonthlyRevenue { get; set; }
		public int PendingOrders { get; set; }
		public int CompletedOrders { get; set; }
		public int CancelledOrders { get; set; }
		public int RefundedOrders { get; set; }
		public OrderFilterViewModel OrderFilter { get; set; } = new();
	}

	public class OrderFilterViewModel
	{
		public int OrderId { get; set; }
		public string CustomerName { get; set; } = string.Empty;
		public DateOnly DateFrom { get; set; }
		public DateOnly DateTo { get; set; }
	}
}
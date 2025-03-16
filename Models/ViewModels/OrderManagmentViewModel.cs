namespace BulkyBooksWeb.Models.ViewModels
{

	namespace BulkyBooksWeb.Models.ViewModels
	{
		public class OrderManagementViewModel
		{
			public IEnumerable<Order> Orders { get; set; } = [];
			public int TotalOrdersMonthly { get; set; }
			public decimal MonthlyRevenue { get; set; }
			public int ProcessingOrders { get; set; }
		}
	}
}
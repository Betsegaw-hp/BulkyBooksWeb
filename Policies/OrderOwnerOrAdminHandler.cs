using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Policies
{
	public class OrderOwnerOrAdminHandler : AuthorizationHandler<OrderOwnerOrAdminRequirement, string>
	{
		// The resource here is the Order's UserId.
		protected override Task HandleRequirementAsync(
			AuthorizationHandlerContext context,
			OrderOwnerOrAdminRequirement requirement,
			string orderOwnerId)
		{

			if (context.User.IsInRole("Admin"))
			{
				context.Succeed(requirement);
				return Task.CompletedTask;
			}

			// Otherwise, check if the user id == owner ID.
			var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (!string.IsNullOrEmpty(userId) && userId == orderOwnerId)
			{
				context.Succeed(requirement);
			}

			return Task.CompletedTask;
		}
	}

}
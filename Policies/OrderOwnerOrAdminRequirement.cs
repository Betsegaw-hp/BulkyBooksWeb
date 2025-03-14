using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Policies
{
	public class OrderOwnerOrAdminRequirement : IAuthorizationRequirement
	{
		// No additional properties needed
	}
}
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Policies
{
    public class BookOwnerOrAdminRequirement : IAuthorizationRequirement
    {
        // No additional properties needed
    }
}
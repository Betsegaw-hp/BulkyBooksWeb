using System.Security.Claims;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Policies
{
    public class BookOwnerOrAdminHandler : AuthorizationHandler<BookOwnerOrAdminRequirement, int>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            BookOwnerOrAdminRequirement requirement,
            int authorId)
        {
            // Check if the user is an admin
            if (context.User.IsInRole("admin"))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Otherwise, check if the user ID matches the book's owner ID
            var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out int userId))
            {
                if (userId == authorId)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }
}
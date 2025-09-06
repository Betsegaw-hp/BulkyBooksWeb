using System.Security.Claims;
using BulkyBooksWeb.Models;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Policies
{
    public class BookOwnerOrAdminHandler : AuthorizationHandler<BookOwnerOrAdminRequirement, string>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            BookOwnerOrAdminRequirement requirement,
            string authorId)
        {
            // Check if the user is an admin
            if (context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Otherwise, check if the user ID matches the book's owner ID
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId) && userId == authorId)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
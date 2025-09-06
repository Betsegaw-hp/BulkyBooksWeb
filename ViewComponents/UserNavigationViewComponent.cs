using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using BulkyBooksWeb.Models;
using System.Security.Claims;

namespace BulkyBooksWeb.ViewComponents
{
    public class UserNavigationViewComponent : ViewComponent
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserNavigationViewComponent(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IViewComponentResult> InvokeAsync()
        {
            var model = new UserNavigationViewModel();
            
            if (User.Identity?.IsAuthenticated == true)
            {
                var claimsPrincipal = User as ClaimsPrincipal;
                var userId = claimsPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (userId != null)
                {
                    var user = await _userManager.FindByIdAsync(userId);
                    if (user != null)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);
                        model.User = user;
                        model.Roles = userRoles.ToList();
                    }
                }
            }
            
            return View(model);
        }
    }

    public class UserNavigationViewModel
    {
        public ApplicationUser User { get; set; } = new();
        public List<string> Roles { get; set; } = new();
    }
}

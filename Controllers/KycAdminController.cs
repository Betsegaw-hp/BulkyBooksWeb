using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Controllers
{
    [Authorize(Roles = "Admin")]
    public class KycAdminController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public KycAdminController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public IActionResult Pending()
        {
            var pendingUsers = _userManager.Users.Where(u => u.KycStatus == KycStatus.Pending).ToList();
            return View(pendingUsers);
        }

        [HttpGet]
        public async Task<IActionResult> Review(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();
            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Approve(string userId, string? notes)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();
            user.KycStatus = KycStatus.Verified;
            user.KycVerifiedAt = DateTime.UtcNow;
            user.KycAdminNotes = notes;
            await _userManager.UpdateAsync(user);
            TempData["Message"] = $"KYC for {user.UserName} approved.";
            return RedirectToAction("Pending");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Reject(string userId, string? notes)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();
            user.KycStatus = KycStatus.Rejected;
            user.KycAdminNotes = notes;
            await _userManager.UpdateAsync(user);
            TempData["Message"] = $"KYC for {user.UserName} rejected.";
            return RedirectToAction("Pending");
        }
    }
}

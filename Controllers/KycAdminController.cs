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
        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();
            var pending = users.Count(u => u.KycStatus == KycStatus.Pending);
            var verified = users.Count(u => u.KycStatus == KycStatus.Verified);
            var rejected = users.Count(u => u.KycStatus == KycStatus.Rejected);
            ViewBag.Pending = pending;
            ViewBag.Verified = verified;
            ViewBag.Rejected = rejected;
            return View(users);
        }

        [HttpGet]
        public IActionResult FilterKyc(KycStatus? status)
        {
            Console.WriteLine($"Filtering KYC with status: {status}");
            var users = _userManager.Users.AsQueryable();
            if (status.HasValue)
            {
                users = users.Where(u => u.KycStatus == status.Value);
            }
            return View("Index", users.ToList());
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
            return RedirectToAction("Index");
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
            return RedirectToAction("Index");
        }
    }
}

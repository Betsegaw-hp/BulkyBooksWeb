using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Models.ViewModels;
using BulkyBooksWeb.Services;
using BulkyBooksWeb.Configuration;

namespace BulkyBooksWeb.Controllers
{
    [Authorize(Roles = "Author")]
    public class KycController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IFileUploadService _fileUploadService;
        private readonly AzureConfiguration _azureConfig;

        public KycController(
            UserManager<ApplicationUser> userManager, 
            IFileUploadService fileUploadService,
            AzureConfiguration azureConfig)
        {
            _userManager = userManager;
            _fileUploadService = fileUploadService;
            _azureConfig = azureConfig;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return RedirectToAction("Submit");
        }

        [HttpGet]
        public async Task<IActionResult> Submit()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();
            var vm = new KycSubmissionViewModel
            {
                ExistingIdProofPath = user.IdProofPath,
                ExistingAddressProofPath = user.AddressProofPath,
                ExistingAuthorPhotoPath = user.AuthorPhotoPath,
                KycStatus = user.KycStatus,
                KycAdminNotes = user.KycAdminNotes
            };
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Submit(KycSubmissionViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            // Save uploaded files if present
            if (model.IdProof != null)
                user.IdProofPath = await SaveFile(model.IdProof, "idproofs");
            if (model.AddressProof != null)
                user.AddressProofPath = await SaveFile(model.AddressProof, "addressproofs");
            if (model.AuthorPhoto != null)
                user.AuthorPhotoPath = await SaveFile(model.AuthorPhoto, "authorphotos");

            user.KycStatus = KycStatus.Pending;
            user.KycAdminNotes = null;
            await _userManager.UpdateAsync(user);
            TempData["Message"] = "KYC submitted. Awaiting admin review.";
            return RedirectToAction("Submit");
        }

        private async Task<string> SaveFile(IFormFile file, string folder)
        {
            string containerName = folder switch
            {
                "idproofs" => _azureConfig.BlobStorage.Containers.IdProofs,
                "addressproofs" => _azureConfig.BlobStorage.Containers.AddressProofs,
                "authorphotos" => _azureConfig.BlobStorage.Containers.AuthorPhotos,
                _ => throw new ArgumentException($"Unknown folder type: {folder}")
            };

            return await _fileUploadService.SaveFileAsync(file, containerName);
        }
    }
}

using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Models;
using BulkyBooksWeb.Configuration;
using BulkyBooksWeb.Data;
using Microsoft.EntityFrameworkCore;

namespace BulkyBooksWeb.Controllers
{
    [Authorize]
    public class FileController : Controller
    {
        private readonly BlobServiceClient _blobServiceClient;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AzureConfiguration _azureConfig;
        private readonly ApplicationDbContext _db;

        public FileController(BlobServiceClient blobServiceClient, UserManager<ApplicationUser> userManager, AzureConfiguration azureConfig, ApplicationDbContext db)
        {
            _blobServiceClient = blobServiceClient;
            _userManager = userManager;
            _azureConfig = azureConfig;
            _db = db;
        }

        // Book PDF (private)
        [HttpGet]
        public async Task<IActionResult> BookPdf(string fileName, bool inline = false)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            bool isAdmin = User.IsInRole("Admin");
            bool isAuthor = await IsAuthorOfBook(user, fileName);
            bool isCustomer = await HasOrderedBook(user, fileName);

            if (!isAdmin && !isAuthor && !isCustomer)
                return Forbid();

            var container = _azureConfig.BlobStorage.Containers.BookPdfs;
            var blobClient = _blobServiceClient.GetBlobContainerClient(container).GetBlobClient(fileName);
            if (!await blobClient.ExistsAsync())
                return NotFound();

            var download = await blobClient.DownloadAsync();
            var contentType = download.Value.Details.ContentType ?? "application/pdf";
            var disposition = inline ? "inline" : "attachment";
            Response.Headers.Append("Content-Disposition", $"{disposition}; filename=\"{fileName}\"");
            return File(download.Value.Content, contentType);
        }

        // KYC Document (private)
        [HttpGet]
        public async Task<IActionResult> KycDoc(string fileName, string type, bool inline = false)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            bool isAdmin = User.IsInRole("Admin");
            bool isOwner = await IsOwnerOfKyc(user, fileName, type);

            if (!isAdmin && !isOwner)
                return Forbid();

            string container = type switch
            {
                "idproofs" => _azureConfig.BlobStorage.Containers.IdProofs,
                "addressproofs" => _azureConfig.BlobStorage.Containers.AddressProofs,
                "authorphotos" => _azureConfig.BlobStorage.Containers.AuthorPhotos,
                _ => _azureConfig.BlobStorage.Containers.IdProofs
            };
            var blobClient = _blobServiceClient.GetBlobContainerClient(container).GetBlobClient(fileName);
            if (!await blobClient.ExistsAsync())
                return NotFound();

            var download = await blobClient.DownloadAsync();
            var contentType = download.Value.Details.ContentType ?? "application/octet-stream";
            var disposition = inline ? "inline" : "attachment";
            Response.Headers.Append("Content-Disposition", $"{disposition}; filename=\"{fileName}\"");
            return File(download.Value.Content, contentType);
        }

        // --- Helpers ---
        private async Task<bool> IsAuthorOfBook(ApplicationUser user, string fileName)
        {
            // Find book by PDF fileName and check author
            var book = await _db.Books.FirstOrDefaultAsync(b => b.PdfFilePath != null && b.PdfFilePath.Contains(fileName));
            return book != null && book.AuthorId == user.Id;
        }

        private async Task<bool> HasOrderedBook(ApplicationUser user, string fileName)
        {
            // Check if user has an order with this book's PDF
            var orders = await _db.Orders.Include(o => o.OrderItems).Where(o => o.UserId == user.Id).ToListAsync();
            foreach (var order in orders)
            {
                foreach (var item in order.OrderItems)
                {
                    var book = await _db.Books.FindAsync(item.BookId);
                    if (book != null && book.PdfFilePath != null && book.PdfFilePath.Contains(fileName))
                        return true;
                }
            }
            return false;
        }

        private async Task<bool> IsOwnerOfKyc(ApplicationUser user, string fileName, string type)
        {
            // Check if the file belongs to the current user
            var dbUser = await _db.Users.FirstOrDefaultAsync(u => u.Id == user.Id);
            if (dbUser == null) return false;
            return type switch
            {
                "idproofs" => dbUser.IdProofPath != null && dbUser.IdProofPath.Contains(fileName),
                "addressproofs" => dbUser.AddressProofPath != null && dbUser.AddressProofPath.Contains(fileName),
                "authorphotos" => dbUser.AuthorPhotoPath != null && dbUser.AuthorPhotoPath.Contains(fileName),
                _ => false
            };
        }
    }
}

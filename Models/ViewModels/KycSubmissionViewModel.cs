using Microsoft.AspNetCore.Http;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Models.ViewModels
{
    public class KycSubmissionViewModel
    {
        public IFormFile? IdProof { get; set; }
        public IFormFile? AddressProof { get; set; }
        public IFormFile? AuthorPhoto { get; set; }
        public string? ExistingIdProofPath { get; set; }
        public string? ExistingAddressProofPath { get; set; }
        public string? ExistingAuthorPhotoPath { get; set; }
        public KycStatus KycStatus { get; set; }
        public string? KycAdminNotes { get; set; }
    }
}

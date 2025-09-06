using Microsoft.AspNetCore.Mvc;

namespace BulkyBooksWeb.Services
{
	public interface IFileUploadService
	{
		Task<string> SaveFileAsync(IFormFile file, string containerName);
		Task<bool> DeleteFileAsync(string fileName, string containerName);
		Task<bool> FileExistsAsync(string fileName, string containerName);
		string GetFileUrl(string fileName, string containerName);
	}
}

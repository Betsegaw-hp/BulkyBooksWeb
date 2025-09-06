namespace BulkyBooksWeb.Services
{
	public interface IBlobStorageService
	{
		Task<string> UploadFileAsync(IFormFile file, string containerName, string? fileName = null);
		Task DeleteFileAsync(string fileUrl, string containerName);
		Task<bool> FileExistsAsync(string fileUrl, string containerName);
	}
}

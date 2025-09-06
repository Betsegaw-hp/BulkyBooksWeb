using BulkyBooksWeb.Configuration;

namespace BulkyBooksWeb.Services
{
	public class FileUploadService : IFileUploadService
	{
		private readonly IBlobStorageService _blobStorageService;
		private readonly AzureConfiguration _azureConfig;
		private readonly ILogger<FileUploadService> _logger;

		public FileUploadService(
			IBlobStorageService blobStorageService,
			AzureConfiguration azureConfig,
			ILogger<FileUploadService> logger)
		{
			_blobStorageService = blobStorageService;
			_azureConfig = azureConfig;
			_logger = logger;
		}

		public async Task<string> SaveFileAsync(IFormFile file, string containerName)
		{
			try
			{
				if (file == null || file.Length == 0)
				{
					throw new ArgumentException("File is null or empty", nameof(file));
				}

				// Generate unique filename
				var fileName = $"{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";

				// Upload to Azure Blob Storage
				var fileUrl = await _blobStorageService.UploadFileAsync(file, containerName, fileName);

				_logger.LogInformation("File uploaded successfully: {FileName} to container: {ContainerName}", fileName, containerName);
				return fileUrl;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error uploading file to container: {ContainerName}", containerName);
				throw;
			}
		}

		public async Task<bool> DeleteFileAsync(string fileUrl, string containerName)
		{
			try
			{
				if (string.IsNullOrEmpty(fileUrl))
					return false;

				string fileName;
				
				// Handle both old local paths and new blob URLs
				if (fileUrl.StartsWith("/uploads/") || fileUrl.StartsWith("uploads/"))
				{
					// Old local path format: /uploads/avatars/filename.jpg
					fileName = Path.GetFileName(fileUrl);
				}
				else if (Uri.TryCreate(fileUrl, UriKind.Absolute, out var uri))
				{
					// New blob URL format: https://account.blob.core.windows.net/container/filename.jpg
					fileName = Path.GetFileName(uri.LocalPath);
				}
				else
				{
					// Assume it's just a filename
					fileName = fileUrl;
				}
				
				await _blobStorageService.DeleteFileAsync(fileName, containerName);
				
				_logger.LogInformation("File deleted successfully: {FileName} from container: {ContainerName}", fileName, containerName);
				
				return true;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error deleting file: {FileUrl} from container: {ContainerName}", fileUrl, containerName);
				return false;
			}
		}

		public async Task<bool> FileExistsAsync(string fileUrl, string containerName)
		{
			try
			{
				if (string.IsNullOrEmpty(fileUrl))
					return false;

				string fileName;
				
				// Handle both old local paths and new blob URLs
				if (fileUrl.StartsWith("/uploads/") || fileUrl.StartsWith("uploads/"))
				{
					// Old local path format: /uploads/avatars/filename.jpg
					fileName = Path.GetFileName(fileUrl);
				}
				else if (Uri.TryCreate(fileUrl, UriKind.Absolute, out var uri))
				{
					// New blob URL format: https://account.blob.core.windows.net/container/filename.jpg
					fileName = Path.GetFileName(uri.LocalPath);
				}
				else
				{
					// Assume it's just a filename
					fileName = fileUrl;
				}
				
				return await _blobStorageService.FileExistsAsync(fileName, containerName);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error checking file existence: {FileUrl} in container: {ContainerName}", fileUrl, containerName);
				return false;
			}
		}

		public string GetFileUrl(string fileName, string containerName)
		{
			// This would return the full blob URL
			// For now, return a placeholder - you might want to implement this based on your blob service
			return $"https://yourstorageaccount.blob.core.windows.net/{containerName}/{fileName}";
		}
	}
}

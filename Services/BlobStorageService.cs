using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace BulkyBooksWeb.Services
{
	public class BlobStorageService : IBlobStorageService
	{
		private readonly BlobServiceClient _blobServiceClient;
		private readonly ILogger<BlobStorageService> _logger;

		public BlobStorageService(BlobServiceClient blobServiceClient, ILogger<BlobStorageService> logger)
		{
			_blobServiceClient = blobServiceClient;
			_logger = logger;
		}

		public async Task<string> UploadFileAsync(IFormFile file, string containerName, string? fileName = null)
		{
			try
			{
				if (file == null || file.Length == 0)
				{
					throw new ArgumentException("File is null or empty", nameof(file));
				}

				_logger.LogInformation("Starting file upload. File: {FileName}, Container: {ContainerName}", file.FileName, containerName);
				
				// Generate unique filename if not provided
				fileName ??= $"{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";

				_logger.LogInformation("Generated filename: {FileName}", fileName);

				// Get container client
				var containerClient = _blobServiceClient.GetBlobContainerClient(containerName);
				_logger.LogInformation("Creating container if not exists: {ContainerName}", containerName);
				await containerClient.CreateIfNotExistsAsync(PublicAccessType.Blob);

				// Get blob client
				var blobClient = containerClient.GetBlobClient(fileName);

				// Set content type based on file extension
				var blobHttpHeaders = new BlobHttpHeaders
				{
					ContentType = GetContentType(file.FileName ?? string.Empty)
				};

				// Upload file
				using var stream = file.OpenReadStream();
				await blobClient.UploadAsync(stream, new BlobUploadOptions
				{
					HttpHeaders = blobHttpHeaders
				});

				_logger.LogInformation("File {FileName} uploaded successfully to container {ContainerName}", fileName, containerName);
				return blobClient.Uri.ToString();
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error uploading file {FileName} to container {ContainerName}", fileName, containerName);
				throw;
			}
		}

		public async Task DeleteFileAsync(string fileUrl, string containerName)
		{
			try
			{
				var fileName = Path.GetFileName(new Uri(fileUrl).LocalPath);
				var containerClient = _blobServiceClient.GetBlobContainerClient(containerName);
				var blobClient = containerClient.GetBlobClient(fileName);

				await blobClient.DeleteIfExistsAsync();
				_logger.LogInformation("File {FileName} deleted successfully from container {ContainerName}", fileName, containerName);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error deleting file {FileUrl} from container {ContainerName}", fileUrl, containerName);
				throw;
			}
		}

		public async Task<bool> FileExistsAsync(string fileUrl, string containerName)
		{
			try
			{
				var fileName = Path.GetFileName(new Uri(fileUrl).LocalPath);
				var containerClient = _blobServiceClient.GetBlobContainerClient(containerName);
				var blobClient = containerClient.GetBlobClient(fileName);

				var response = await blobClient.ExistsAsync();
				return response.Value;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error checking if file {FileUrl} exists in container {ContainerName}", fileUrl, containerName);
				return false;
			}
		}

		private static string GetContentType(string fileName)
		{
			var extension = Path.GetExtension(fileName).ToLowerInvariant();
			return extension switch
			{
				".jpg" or ".jpeg" => "image/jpeg",
				".png" => "image/png",
				".gif" => "image/gif",
				".pdf" => "application/pdf",
				".txt" => "text/plain",
				".json" => "application/json",
				".xml" => "application/xml",
				_ => "application/octet-stream"
			};
		}
	}
}

namespace BulkyBooksWeb.Configuration
{
	public class AzureConfiguration
	{
		public const string SectionName = "Azure";
		
		public BlobStorageConfiguration BlobStorage { get; set; } = new();
	}

	public class BlobStorageConfiguration
	{
		public string ConnectionString { get; set; } = string.Empty;
		public ContainersConfiguration Containers { get; set; } = new();
	}

	public class ContainersConfiguration
	{
		public string BookCovers { get; set; } = "book-covers";
		public string BookPdfs { get; set; } = "book-pdfs";
		public string AddressProofs { get; set; } = "address-proofs";
		public string AuthorPhotos { get; set; } = "author-photos";
		public string Avatars { get; set; } = "avatars";
		public string IdProofs { get; set; } = "id-proofs";
	}
}

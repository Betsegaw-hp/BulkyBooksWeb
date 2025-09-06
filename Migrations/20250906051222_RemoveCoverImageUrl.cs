using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BulkyBooksWeb.Migrations
{
    /// <inheritdoc />
    public partial class RemoveCoverImageUrl : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Clear related data first to avoid foreign key constraint issues
            migrationBuilder.Sql("DELETE FROM Carts");
            migrationBuilder.Sql("DELETE FROM Books");
            
            migrationBuilder.DropColumn(
                name: "CoverImageUrl",
                table: "Books");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CoverImageUrl",
                table: "Books",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}

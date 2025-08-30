using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BulkyBooksWeb.Migrations
{
    /// <inheritdoc />
    public partial class AddKycFieldsToApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AddressProofPath",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AuthorPhotoPath",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IdProofPath",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "KycAdminNotes",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "KycStatus",
                table: "AspNetUsers",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "KycVerifiedAt",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AddressProofPath",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "AuthorPhotoPath",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IdProofPath",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "KycAdminNotes",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "KycStatus",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "KycVerifiedAt",
                table: "AspNetUsers");
        }
    }
}

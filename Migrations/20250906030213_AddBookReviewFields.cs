using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BulkyBooksWeb.Migrations
{
    /// <inheritdoc />
    public partial class AddBookReviewFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AdminReviewComments",
                table: "Books",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PdfFilePath",
                table: "Books",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ReviewedAt",
                table: "Books",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ReviewedBy",
                table: "Books",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Status",
                table: "Books",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AdminReviewComments",
                table: "Books");

            migrationBuilder.DropColumn(
                name: "PdfFilePath",
                table: "Books");

            migrationBuilder.DropColumn(
                name: "ReviewedAt",
                table: "Books");

            migrationBuilder.DropColumn(
                name: "ReviewedBy",
                table: "Books");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "Books");
        }
    }
}

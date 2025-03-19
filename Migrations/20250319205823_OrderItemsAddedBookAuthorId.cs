using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BulkyBooksWeb.Migrations
{
    /// <inheritdoc />
    public partial class OrderItemsAddedBookAuthorId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_OrderItems_Books_BookId",
                table: "OrderItems");

            migrationBuilder.DropIndex(
                name: "IX_OrderItems_BookId",
                table: "OrderItems");

            migrationBuilder.AddColumn<int>(
                name: "BookAuthorId",
                table: "OrderItems",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BookAuthorId",
                table: "OrderItems");

            migrationBuilder.CreateIndex(
                name: "IX_OrderItems_BookId",
                table: "OrderItems",
                column: "BookId");

            migrationBuilder.AddForeignKey(
                name: "FK_OrderItems_Books_BookId",
                table: "OrderItems",
                column: "BookId",
                principalTable: "Books",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

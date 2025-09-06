using Microsoft.AspNetCore.Mvc;
using BulkyBooksWeb.Services;
using Microsoft.AspNetCore.Authorization;

namespace BulkyBooksWeb.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MigrationController : ControllerBase
    {
        private readonly UserMigrationService _migrationService;
        private readonly IWebHostEnvironment _environment;

        public MigrationController(UserMigrationService migrationService, IWebHostEnvironment environment)
        {
            _migrationService = migrationService;
            _environment = environment;
        }

        [HttpPost("migrate-users")]
        public async Task<IActionResult> MigrateUsers()
        {
            // Only allow in development
            if (!_environment.IsDevelopment())
            {
                return Forbid();
            }

            try
            {
                await _migrationService.MigrateExistingUsers();
                return Ok(new { message = "Users migrated successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }
}

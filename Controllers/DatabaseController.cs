using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using BulkyBooksWeb.Data;
using BulkyBooksWeb.Models;

namespace BulkyBooksWeb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DatabaseController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public DatabaseController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [HttpPost("ensure-created")]
        public async Task<IActionResult> EnsureCreated()
        {
            try
            {
                // Ensure the database and tables are created
                await _context.Database.EnsureCreatedAsync();
                
                // Check if AspNetUsers table exists
                var hasUsers = await _context.Users.AnyAsync();
                
                return Ok(new { Message = "Database ensured created", HasUsers = hasUsers });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = ex.Message });
            }
        }

        [HttpGet("tables")]
        public async Task<IActionResult> GetTables()
        {
            try
            {
                var sql = @"
                    SELECT TABLE_NAME 
                    FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_TYPE = 'BASE TABLE' 
                    ORDER BY TABLE_NAME";
                
                var tables = await _context.Database.SqlQueryRaw<string>(sql).ToListAsync();
                
                return Ok(new { Tables = tables });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = ex.Message });
            }
        }
    }
}

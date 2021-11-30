using AccountManagement.Data;
using AccountManagement.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ApiDbContext _context;
        public AccountController(ApiDbContext context)
        {
            _context = context;
        }

        // 
        [HttpGet]
        public async Task<IActionResult> GetAccountList()
        {
            var items = await _context.Account.ToListAsync();
            return Ok(items);
        }

        [HttpPost]
        public async Task<IActionResult> CreateAccount(Account data)
        {
            if (ModelState.IsValid)
            {
                await _context.Account.AddAsync(data);
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetItem", new { data.Id }, data);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetAccount(int id)
        {
            var item = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (item == null)
                return NotFound();

            return Ok(item);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateItem(int id, Account account)
        {
            if (id != account.Id)
                return BadRequest();

            var existItem = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (existItem == null)
                return NotFound();

            existItem.FullName = account.FullName;
            existItem.Email = account.Email;
            existItem.Phone = account.Phone;
            existItem.Avatar = account.Avatar;
            existItem.LastAccess = account.LastAccess;

            // Implement the changes on the database level
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var existItem = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (existItem == null)
                return NotFound();

            _context.Account.Remove(existItem);
            await _context.SaveChangesAsync();

            return Ok(existItem);
        }

    }
}
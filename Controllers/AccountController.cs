using AccountManagement.Data;
using AccountManagement.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DotNet.Controllers
{
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ApiDbContext _context;
        public AccountController(ApiDbContext context)
        {
            _context = context;
        }

        
        [HttpGet("account/all")]
        public async Task<IActionResult> GetAccountList()
        {
            var items = await _context.Account.ToListAsync();
            return Ok(items);
        }

        // Sort List Account
        [HttpGet("account/sort")]
        public async Task<IActionResult> GetSortedAccountList()
        {
            var items = await _context.Account.ToListAsync();
            items.Sort();
            return Ok(items);
        }

        [HttpPost("account/create")]
        public async Task<IActionResult> CreateAccount(Account data)
        {
            if (ModelState.IsValid)
            {
                await _context.Account.AddAsync(data);
                await _context.SaveChangesAsync();

                return CreatedAtAction("CreateAccount", new { data.Id }, data);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };
        }

        [HttpGet("account/{id}")]
        public async Task<IActionResult> GetAccount(int id)
        {
            var item = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (item == null)
                return NotFound();

            return Ok(item);
        }
        
        [HttpGet("account/byname/{fullname}")]
        public async Task<IActionResult> GetAccountByName(string fullname)
        {
            //var item = await _context.Account.FindAsync(x => x.FullName.Contains(fullname));
            var listAccount = await _context.Account.ToListAsync();
            if (listAccount == null) return NotFound();

            listAccount = listAccount.Where(x => (x.FullName.Contains(fullname))).ToList();

            return Ok(listAccount);
        }

        [HttpGet("account/byemail/{email}")]
        public async Task<IActionResult> GetAccountByEmail(string email)
        {
            var item = await _context.Account.FirstOrDefaultAsync(x => x.Email == email);

            if (item == null)
                return NotFound();

            return Ok(item);
        }

        [HttpGet("account/byphone/{phone}")]
        public async Task<IActionResult> GetAccountByPhone(string phone)
        {
            var item = await _context.Account.FirstOrDefaultAsync(x => x.Phone == phone);

            if (item == null)
                return NotFound();

            return Ok(item);
        }

        [HttpPut("account/{id}")]
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

        [HttpDelete("account/{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var existItem = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (existItem == null)
                return NotFound();

            _context.Account.Remove(existItem);
            await _context.SaveChangesAsync();

            return Ok(existItem);
        }


         [HttpGet("account/filter/{timemin}/{timemax}")]
        public async Task<IActionResult> GetFilterByLastAccess(DateTime timemin,DateTime timemax)
        {
            var listAccount = await _context.Account.ToListAsync();
         
            listAccount = listAccount.Where(x => (x.LastAccess >= timemin && x.LastAccess <= timemax)).ToList();
            return Ok(listAccount);
            

            
        }
        
    }
}
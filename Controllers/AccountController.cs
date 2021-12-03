using AccountManagement.Configuration;
using AccountManagement.Data;
using AccountManagement.Models;
using AccountManagement.Models.DTOs.Responses;
using AccountManager.Models.DTOs.Request;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace DotNet.Controllers
{
    
    [ApiController]

    public class AccountController : ControllerBase
    {
        private readonly JwtConfig _jwtConfig;
        private readonly ApiDbContext _context;
        public AccountController(ApiDbContext context, IOptionsMonitor<JwtConfig> optionsMonitor)
        {
            _context = context;
            _jwtConfig = optionsMonitor.CurrentValue;
        }

      
        
        [HttpGet("account/all")]
        public async Task<IActionResult> GetAccountList()
        {
            var items = await _context.Account.ToListAsync(); 
            return Ok(items);
        }

        /* Sort List Account
        [HttpGet("account/sort")]
        public async Task<IActionResult> GetSortedAccountList()
        {
            var items = await _context.Account.ToListAsync();
            return Ok(items);
        }
        */

        [HttpPost("account/create")]
        public async Task<IActionResult> CreateAccount([FromForm]Account data, [FromForm]IFormFile file)
        {
            var FileDic = "Files";
            var FilePath = Path.Combine(Directory.GetCurrentDirectory(), FileDic);
                      
            if (!Directory.Exists(FilePath))
            {
                Directory.CreateDirectory(FilePath);
            }
           
            if (file != null)
            {
                if(file.Length > 0)
                {
                    var RandomFileName = new Random().Next() + "_" + Regex.Replace(file.FileName.Trim(), @"[^a-zA-Z0-9.]", "");
                    var fullFilePath = Path.Combine(FilePath, RandomFileName);

                    using (FileStream fs = System.IO.File.Create(fullFilePath))
                    {
                        file.CopyTo(fs);
                    }

                    data.Avatar = fullFilePath;
                }
            }
    
            
           
            if (ModelState.IsValid)
            {
                await _context.Account.AddAsync(data);
                await _context.SaveChangesAsync();

                return Ok(data);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };
        }


        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] AccountLoginDto user) // AccountLoginRequest request
        {
            if (ModelState.IsValid)
            {
                
                var items = await _context.Account.FirstOrDefaultAsync(x => x.Email == user.Email);

                if (items == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>() {
                                "Invalid login request"
                            },
                        Success = false
                    });
                }

               var existAcc =  await _context.Account.FirstOrDefaultAsync(x => (x.Email == items.Email && x.Password == items.Password));

                if (existAcc == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>() {
                                "Invalid login request"
                            },
                        Success = false
                    });
                }

                var jwtToken = GenerateJwtToken(existAcc);

                return Ok(new RegistrationResponse()
                {
                    Success = true,
                    Token = jwtToken
                });
            }

            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>() {
                        "Invalid payload"
                    },
                Success = false
            });
        }

        private string GenerateJwtToken(Account user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(6),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("account/{id}")]
        public async Task<IActionResult> GetAccount(int id)
        {
            var item = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (item == null)
                return NotFound();

            //item.Avatar = this.GetImage(Convert.ToBase64String(item.Avatar));

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
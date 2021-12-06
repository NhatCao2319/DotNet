using AccountManagement.Configuration;
using AccountManagement.Data;
using AccountManagement.Models;
using AccountManagement.Models.DTOs;
using AccountManagement.Models.DTOs.Responses;
using AccountManager.Models.DTOs.Request;
using AutoMapper;
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
using BCrypt.Net;
using AccountManagement;

namespace DotNet.Controllers
{
    
    [ApiController]
    

    public class AccountController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly JwtConfig _jwtConfig;
        private readonly ApiDbContext _context;
        public AccountController(ApiDbContext context, IOptionsMonitor<JwtConfig> optionsMonitor, IMapper mapper)
        {
            _context = context;
            _jwtConfig = optionsMonitor.CurrentValue;
            _mapper = mapper;
        }
        
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] AccountLoginDto user) // AccountLoginRequest request
        { 
            if (ModelState.IsValid)
            {

                Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Email == user.Email || x.Phone == user.Phone);

                if (acc == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>() {
                                "Invalid login request"
                            },
                        Success = false
                    });
                }

                bool isValidPass = BCrypt.Net.BCrypt.Verify(user.Password, acc.Password);


                if (isValidPass == false)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>() {
                                "Invalid login request"
                            },
                        Success = false
                    });
                }

                var jwtToken = GenerateJwtToken(acc);
               



                await UpdateLastAccess(acc);


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
        
        
        [HttpGet("account/all")]
        public async Task<IActionResult> GetAccountList([FromQuery]int pageIndex,[FromQuery] int pageSize)
        {
            IQueryable<Account> list =  _context.Account.AsQueryable();
            PaginatedList<Account> items = await PaginatedList<Account>.CreateAsync(list, pageIndex,pageSize);
            //PaginatedList<Account> items = PaginatedList<Account>.Create(_context.Account.ToList(), pageIndex, pageSize);
            return Ok(items);
        }

        //Sort List Account
        [Authorize(Roles = "Admin")]
        [HttpGet("account/sort")]
        public async Task<IActionResult> GetSortedAccountList()
        {
            List<Account> items = await _context.Account.ToListAsync();
            List<Account> SortItems = items.OrderBy(x => x.FullName).ToList();
            return Ok(SortItems);
        }
        

        [HttpPost("account/create")]
        [AllowAnonymous]
        public async Task<IActionResult> CreateAccount([FromForm]AccountRequest data)
        {
            string FileDic = "Files";
            string FilePath = Path.Combine("", FileDic);
            string AvatarPath = "";
                      
            if (!Directory.Exists(FilePath))
            {
                Directory.CreateDirectory(FilePath);
            }
           
            if (data.Avatar != null)
            {
                if(data.Avatar.Length > 0)
                {
                    string RandomFileName = new Random().Next() + "_" + Regex.Replace(data.Avatar.FileName.Trim(), @"[^a-zA-Z0-9.]", "");
                    string fullFilePath = Path.Combine(FilePath, RandomFileName);

                    using (FileStream fs = System.IO.File.Create(fullFilePath))
                    {
                        data.Avatar.CopyTo(fs);
                    }
                    AvatarPath = fullFilePath;
                }
            }
    
            
           
            if (ModelState.IsValid)
            {
               // AccountRequest accountRe = _mapper.Map<AccountRequest>(data);
                Account account = _mapper.Map<Account>(data);
                account.Avatar = AvatarPath;
                account.Password = BCrypt.Net.BCrypt.HashPassword(data.Password);
               
                await _context.Account.AddAsync(account);

                await _context.SaveChangesAsync();

                return Ok(account);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };
        }

        private string getFilePath(IFormFile file)
        {
            string FileDic = "Files";
            string FilePath = Path.Combine("", FileDic);
            string AvatarPath = "";

            if (!Directory.Exists(FilePath))
            {
                Directory.CreateDirectory(FilePath);
            }

            if (file != null)
            {
                if (file.Length > 0)
                {
                    string RandomFileName = new Random().Next() + "_" + Regex.Replace(file.FileName, @"[^a-zA-Z0-9.]", "");
                    string fullFilePath = Path.Combine(FilePath, RandomFileName);

                    using (FileStream fs = System.IO.File.Create(fullFilePath))
                    {
                        file.CopyTo(fs);
                    }
                    AvatarPath = fullFilePath;
                }
            }
            return AvatarPath;
        }

        private async Task<IActionResult> UpdateLastAccess(Account account)
        {
            if (account == null)
                return BadRequest();

            account.LastAccess = DateTime.Now;

            // Implement the changes on the database level
            await _context.SaveChangesAsync();

            return NoContent();
        }


        private string GenerateJwtToken(Account user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id.ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Phone),
                    new Claim(ClaimTypes.Role,"Admin","User"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddSeconds(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Authorize(Roles = "Admin")]
        [HttpGet("account/{id}")]
        public async Task<IActionResult> GetAccount(int id)
        {
            Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (acc == null)
                return NotFound();

            return Ok(acc);
        }
        [Authorize(Roles = "Admin")]
        [HttpGet("account/search/{key}")]
        public async Task<IActionResult> GetAccountByName(string key)
        {
            List<Account> listAccount = await _context.Account.ToListAsync();
            if (listAccount == null) return NotFound();

            listAccount = listAccount.Where(acc => (acc.FullName!.ToLower().Contains(key.ToLower())) 
            || (acc.Email!.ToLower().Contains(key.ToLower()))
            || (acc.Phone!.Contains(key))
            || (acc.Id.ToString()! == key)
            ).ToList();

            return Ok(listAccount);
        }
        [Authorize(Roles = "Admin")]
        [HttpGet("account/byemail/{email}")]
        public async Task<IActionResult> GetAccountByEmail(string email)
        {
            Account account = await _context.Account.FirstOrDefaultAsync(x => x.Email == email);

            if (account == null)
                return NotFound();

            return Ok(account);
        }
        [Authorize(Roles = "Admin")]
        [HttpGet("account/byphone/{phone}")]
        public async Task<IActionResult> GetAccountByPhone(string phone)
        {
            Account account = await _context.Account.FirstOrDefaultAsync(x => x.Phone == phone);

            if (account == null)
                return NotFound();

            return Ok(account);
        }
        [Authorize(Roles = "Admin")]
        [HttpPut("account/{id}")]
        public async Task<IActionResult> UpdateItem(int id, Account account)
        {
            if (id != account.Id)
                return BadRequest();

            Account existAccount = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (existAccount == null)
                return NotFound();

            existAccount.FullName = account.FullName;
            existAccount.Email = account.Email;
            existAccount.Phone = account.Phone;
            existAccount.Avatar = account.Avatar;
            existAccount.LastAccess = account.LastAccess;

            // Implement the changes on the database level
            await _context.SaveChangesAsync();

            return Ok(existAccount);
        }
        [Authorize(Roles = "Admin")]
        [HttpDelete("account/{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            Account existAccount = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (existAccount == null)
                return NotFound();

            _context.Account.Remove(existAccount);
            await _context.SaveChangesAsync();

            return Ok(existAccount);
        }

        [Authorize(Roles = "Admin,User")]
        [HttpPatch("account/update/avatar")]
        public async Task<IActionResult> UpdateAvatar(IFormFile file)
        {
            // get value from header
            string id = HttpContext.User.FindFirstValue("Id");
           Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Id.ToString() == id);
           acc.Avatar = getFilePath(file);
           await _context.SaveChangesAsync();

            return Ok(acc);

        }

        [Authorize(Roles = "Admin")]
        [HttpGet("account/filter")]
        public async Task<IActionResult> GetFilterByLastAccess([FromQuery]DateTime timemin,[FromQuery]DateTime timemax)
        {
            List<Account> listAccount = await _context.Account.ToListAsync();
         
            listAccount = listAccount.Where(x => (x.LastAccess >= timemin && x.LastAccess <= timemax)).ToList();
            return Ok(listAccount);
         
        }
        
    }
}
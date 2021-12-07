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
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using AccountManagement.Models.DTOs.Requests;
using System.Net.Mail;
using System.Net;
using WebMatrix.WebData;
using System.Web;

namespace DotNet.Controllers
{
    
    [ApiController]

    public class AccountController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly JwtConfig _jwtConfig;
        private readonly ApiDbContext _context;
        private readonly ILogger<AccountController> logger;
        protected static PasswordRecoveryModel passRequest = new PasswordRecoveryModel();

        public AccountController(ApiDbContext context, IOptionsMonitor<JwtConfig> optionsMonitor, IMapper mapper)
        {
            _context = context;
            _jwtConfig = optionsMonitor.CurrentValue;
            _mapper = mapper;
        }
        
        // LOG IN 
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromForm] AccountLoginDto user) // AccountLoginRequest request
        { 
            if (ModelState.IsValid)
            {

                Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Email == user.Email || x.Phone == user.Phone);

                string role = acc.Role;
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
                var userClaims = new List<Claim>()
                        {
                        new Claim(ClaimTypes.Name, acc.FullName),
                        new Claim(ClaimTypes.Role, acc.Role),
                        };

                var identityAcc = new ClaimsIdentity(userClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                var userPrincipal = new ClaimsPrincipal(identityAcc);
                await HttpContext.SignInAsync(userPrincipal);

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

        // CREATE ACCOUNT
        [HttpPost("account/create")]
        [AllowAnonymous]
        public async Task<IActionResult> CreateAccount([FromForm] AccountRequest data)
        {
            Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Email == data.Email);
            if(acc!= null)
            {
                return BadRequest("Email already exist");
            }

            string FileDic = "Files";
            string FilePath = Path.Combine("", FileDic);
            string AvatarPath = "";

            if (!Directory.Exists(FilePath))
            {
                Directory.CreateDirectory(FilePath);
            }

            if (data.Avatar != null)
            {
                if (data.Avatar.Length > 0)
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
               
                Account account = _mapper.Map<Account>(data);
                account.Avatar = AvatarPath;
                account.Role = "User";
                account.Password = BCrypt.Net.BCrypt.HashPassword(data.Password);
                account.DateCreate = DateTime.Now;

                await _context.Account.AddAsync(account);

                await _context.SaveChangesAsync();

                return Ok(account);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };
        }

        // VALIDATE REQUEST FORGOT PASSWORD
        [HttpPost]
        [AllowAnonymous]
        [Route("account/recoverypassword")]
        public async Task<IActionResult> ResetPassword([FromForm] AccountRecovery accReco)
        {
            if (accReco.Password != accReco.ConfirmPassword)
            {
                return BadRequest("Password confirm must same to password");
            }

            if (DateTime.Compare(passRequest.ExpiredTime, DateTime.Now) > 0)
            {
                if (accReco.OTPCode != passRequest.Code.ToString())
                {
                    return BadRequest("Wrong OTP Code");
                }

                Account account = await _context.Account.FirstOrDefaultAsync(x => x.Email == passRequest.Email);
                if (account == null)
                {
                    return BadRequest("Account not exist");
                }

                account.Password = BCrypt.Net.BCrypt.HashPassword(accReco.Password);
                await _context.SaveChangesAsync();
                return Ok("Update Password Success");
            }
            else
            {
                return BadRequest("Code Expired");
            }           
        }

        // SEND REQUEST FORGOT PASSWORD
        [HttpPost]
        [Route("account/forgotpassword")]
        [AllowAnonymous]
        public async Task<IActionResult> SendForgotPassword([FromForm] string Email)
        {
            if (ModelState.IsValid)
            {
                Account account = await _context.Account.FirstOrDefaultAsync(x => x.Email == Email);
                if(account == null)
                {
                    return BadRequest("Account does not exist");
                }

                var rand = new Random();
                var uid = rand.Next(100000, 1000000);
                var expiredCode = DateTime.Now.AddSeconds(30);

              
                using (SmtpClient client = new SmtpClient("smtp.gmail.com"))
                {
                    client.Port = 587;
                    client.Credentials = new NetworkCredential("thoixuongnguyen@gmail.com", "7G1j9m324567");
                    client.EnableSsl = true;
                    await SendMail("thoixuongnguyen@gmail.com",
                        account.Email,
                        "Reset Password by Code",
                      $"Your password reset code : {uid}" +
                      $" - Your code will expired in 30 seconds",
                        client);
                };
                passRequest.Code = uid.ToString();
                passRequest.Email = account.Email;
                passRequest.ExpiredTime = expiredCode;

                return Ok($"The request has sent to your email - {passRequest.Code}-{expiredCode}-{DateTime.Now}");

            }
            else
            {
                return BadRequest();
            }
            
        }

        // Change Password By User
        [HttpPatch]
        [Route("account/user/changepass")]
        public async Task<ActionResult> ChangePassword([FromForm] ChangePasswordRequest passwordRequest)
        {
            if (string.IsNullOrEmpty(passwordRequest.oldPassword) || string.IsNullOrEmpty(passwordRequest.newPassword))
            {
                return BadRequest("Password Require");
            }

            string id = HttpContext.User.FindFirstValue("id");
            if (id == null)
            {
                return BadRequest();
            }

            Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Id.ToString() == id);
            bool isValidPass = BCrypt.Net.BCrypt.Verify(passwordRequest.oldPassword, acc.Password);

            if (isValidPass == false)
            {
                return BadRequest("Wrong Password");
            }

            acc.Password = BCrypt.Net.BCrypt.HashPassword(passwordRequest.newPassword);

            await _context.SaveChangesAsync();
            return Ok("Password Changed");

        }

        // UPDATE ROLE BY ADMIN
        [Authorize(Roles = "Admin")]
        [HttpPatch("account/setrole")]
        public async Task<IActionResult> GrantPermission([FromForm] string id, [FromForm] string role)
        {
            Account account = await _context.Account.FirstOrDefaultAsync(x => x.Id.ToString() == id);
            account.Role = role;
            await _context.SaveChangesAsync();
            return Ok("Role Updated");
        }

        // UPDATE AVATAR
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

        // Send Email Method
        private async Task<bool> SendMail(string from,string to,string subject,string body, SmtpClient client)
        {
            MailMessage mail = new MailMessage(
                   from: from,
                   to: to,
                   subject: subject,
                   body: body
                   );

            mail.BodyEncoding = System.Text.Encoding.UTF8;
            mail.SubjectEncoding = System.Text.Encoding.UTF8;
            mail.IsBodyHtml = true;
            mail.ReplyToList.Add(new MailAddress(from));
            mail.Sender = new MailAddress(from);
            try
            {
                await client.SendMailAsync(mail);
                return true;
            }
            catch(Exception ex)
            {
                return false;
            }
        }


        [Authorize(Roles = "User")]
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
                    new Claim(ClaimTypes.Role,user.Role),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddSeconds(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }

        private string GeneratePasswordRecoveryToken(string email)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {                 
                    new Claim(ClaimTypes.Email,email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddSeconds(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
        
        // GET ACCOUNT BY ID WITH ADMIN ROLE
        [Authorize(Roles = "Admin")]
        [HttpGet("account/{id}")]
        public async Task<IActionResult> GetAccount(int id)
        {
            Account acc = await _context.Account.FirstOrDefaultAsync(x => x.Id == id);

            if (acc == null)
                return NotFound();

            return Ok(acc);
        }

        // SEARCH BY KEY WITH ADMIN ROLE
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

        // FILTER ACCOUNT BY LAST ACCESS TIME
        [Authorize(Roles = "Admin")]
        [HttpGet("account/filter")]
        public async Task<IActionResult> GetFilterByLastAccess([FromQuery] DateTime timemin, [FromQuery] DateTime timemax)
        {
            List<Account> listAccount = await _context.Account.ToListAsync();

            listAccount = listAccount.Where(x => (x.LastAccess >= timemin && x.LastAccess <= timemax)).ToList();
            return Ok(listAccount);

        }

        // UPDATE ACCOUNT WITH ADMIN ROLE
        [Authorize(Roles = "Admin")]
        [HttpPut("account/editaccount")]
        public async Task<IActionResult> UpdateAccount([FromForm] Account account)
        {
            if(account.Id == null)
            {
                return BadRequest();
            }
            Account existAccount = await _context.Account.FirstOrDefaultAsync(x => x.Id == account.Id);

            if (existAccount == null)
                return BadRequest("Account not exist");

            existAccount.FullName = account.FullName;
            existAccount.Email = account.Email;
            existAccount.Phone = account.Phone;
            existAccount.Avatar = account.Avatar;
            existAccount.LastAccess = account.LastAccess;

            // Implement the changes on the database level
            await _context.SaveChangesAsync();

            return Ok(existAccount);
        }

        // DELETE ACCOUNT BY ADMIN ROLE
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
    
    }
}
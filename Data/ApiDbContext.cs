using AccountManagement.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AccountManagement.Data
{
    public class ApiDbContext : IdentityDbContext
    {
        public virtual DbSet<Account> Account { get; set; }
        public virtual DbSet<PasswordRecoveryModel> PasswordRecovery { get; set; }

        public ApiDbContext(DbContextOptions<ApiDbContext> options)
            : base(options)
        {

        }
    }
}




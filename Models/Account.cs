using System.ComponentModel.DataAnnotations;

namespace AccountManagement.Models
{
    public class Account
    {
        public int Id { get; set; }
        [Required]
        public string? FullName { get; set; }
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        [Phone]
        public string? Phone { get; set; }
        [Required]
        public string Password { get; set; }
        public string? Avatar { get; set; }
        public DateTime LastAccess { get; set; }

    }
}

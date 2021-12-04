using System.ComponentModel.DataAnnotations;

namespace AccountManagement.Models.DTOs
{
    public class AccountRequest
    {
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
        public IFormFile? Avatar { get; set; }
        //public DateTime LastAccess { get; set; }


    }
}

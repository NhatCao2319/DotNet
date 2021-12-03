using System.ComponentModel.DataAnnotations;

namespace AccountManager.Models.DTOs.Request
{
    public class AccountLoginDto
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }


    }
}
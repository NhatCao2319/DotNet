using System.ComponentModel.DataAnnotations;

namespace AccountManager.Models.DTOs.Request
{
    public class AccountLoginDto
    {
      
        public string? Email { get; set; }
        public string? Phone { get; set; }
        [Required]
        public string? Password { get; set; }


    }
}
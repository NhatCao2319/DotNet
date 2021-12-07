using System.ComponentModel.DataAnnotations;

namespace AccountManagement.Models
{
    public class PasswordRecoveryModel
    {
        [Required]
        [EmailAddress]

        public string Email { get; set; }
        public string Code { get; set; }
        public DateTime ExpiredTime { get; set; }

    }
}

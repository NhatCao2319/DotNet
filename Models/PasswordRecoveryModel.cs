using System.ComponentModel.DataAnnotations;

namespace AccountManagement.Models
{
    public class PasswordRecoveryModel
    {
        [Required]
        [EmailAddress]
        [Key]
        public string Email { get; set; }
        public string Code { get; set; }
        public DateTime ExpiredTime { get; set; }
        public int status { get; set; }

        public PasswordRecoveryModel()
        {
            
        }

        public PasswordRecoveryModel(string Email,string Code, DateTime ExpiredTime,int status)
        {
            this.Email = Email;
            this.Code = Code;
            this.ExpiredTime = ExpiredTime;
            this.status = status;
        }

    }
}

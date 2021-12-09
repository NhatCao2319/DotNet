namespace AccountManagement.Models.DTOs.Requests
{
    public class AccountRecovery
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
        public string OTPCode { get; set; }

    }
}

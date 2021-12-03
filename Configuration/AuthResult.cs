using AccountManagement.Models;

namespace AccountManagement.Configuration
{
    public class AuthResult
    {
        public string Token { get; set; }
        public bool Success { get; set; }
        public List<string> Errors { get; set; }

        public Account account { get; set; }
    }
}

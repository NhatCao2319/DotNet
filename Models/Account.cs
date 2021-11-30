namespace AccountManagement.Models
{
    public class Account
    {
        public int Id { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Avatar { get; set; }
        public DateTime LastAccess { get; set; }

    }
}

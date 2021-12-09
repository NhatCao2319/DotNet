using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace AccountManagement.Models
{
    public class Account
    {
        [Key]
        [JsonIgnore]
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
        [JsonIgnore]
        public string Password { get; set; }

        [DefaultValue("User")]
        public string? Role { get; set; }
        public string? Avatar { get; set; }
        [JsonIgnore]
        public DateTime? LastAccess { get; set; }
        [JsonIgnore]
        public DateTime DateCreate { get; set; }

    }
}

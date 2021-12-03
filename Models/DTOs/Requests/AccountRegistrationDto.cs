﻿using System.ComponentModel.DataAnnotations;

namespace AccountManagement.Models.DTOs.Requests
{
    public class AccountRegistrationDto
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        public string Password { get; set; }
      
    }
}

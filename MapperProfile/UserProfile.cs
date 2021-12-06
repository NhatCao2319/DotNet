using AccountManagement.Models;
using AccountManagement.Models.DTOs;
using AutoMapper;

namespace AccountManagement.MapperProfile
{
    public class UserProfile : Profile
    {
        public UserProfile()
        {
            CreateMap<AccountRequest, Account>()
                .ForMember(dest => dest.Avatar,
                opt => opt.Ignore());

   
        }
    }
}

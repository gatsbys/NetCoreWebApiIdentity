using Api.Messages.Identity;
using AutoMapper;

namespace WebApi.ViewModels.Mappings
{
    public class ViewModelToEntityMappingProfile : Profile
    {
        public ViewModelToEntityMappingProfile()
        {
            CreateMap<RegistrationViewModel, User>()
                .ForMember(au => au.UserName, map => map.MapFrom(vm => vm.Email))
                .ForMember(au => au.Email, map => map.MapFrom(vm => vm.Email))
                .ForMember(au => au.Name, map => map.MapFrom(vm => vm.Name))
                .ForMember(au => au.Surname, map => map.MapFrom(vm => vm.Surname));
        }
    }
}

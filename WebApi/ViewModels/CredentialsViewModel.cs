using FluentValidation.Attributes;
using WebApi.ViewModels.Validations;

namespace WebApi.ViewModels
{
    [Validator(typeof(CredentialsViewModelValidator))]
    public class CredentialsViewModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}

using System.Text.RegularExpressions;
using Auth_101.Model.Data;
using ServiceStack;
using ServiceStack.FluentValidation;

namespace Auth_101.Model.Validators
{
    public class CustomerValidator : AbstractValidator<Customer>
    {
        
        public CustomerValidator()
        {
            RuleFor(x => x.Id).NotEqual(default(int));

            RuleSet(ApplyTo.Post | ApplyTo.Put, () => {
                                                          RuleFor(x => x.LastName).NotEmpty().WithErrorCode("ShouldNotBeEmpty");
                                                          RuleFor(x => x.FirstName).NotEmpty().WithMessage("Please specify a first name");
                                                          RuleFor(x => x.Company).NotNull();
                                                          RuleFor(x => x.Discount).NotEqual(0).When(x => x.HasDiscount);
                                                          RuleFor(x => x.Address).Length(20, 250);
                                                          RuleFor(x => x.Postcode).Must(IsAValidPostcode).WithMessage("Please specify a valid postcode");
            });
        }

        static readonly Regex UsPostCodeRegEx = new Regex(@"^\d{5}(-\d{4})?$", RegexOptions.Compiled);

        private static bool IsAValidPostcode(string postcode)
        {
            return !string.IsNullOrEmpty(postcode) && UsPostCodeRegEx.IsMatch(postcode);
        }
    }
}
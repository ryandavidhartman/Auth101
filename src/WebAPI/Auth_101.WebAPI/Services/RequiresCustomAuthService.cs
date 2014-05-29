using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [Authenticate(Provider = "custom")]
    public class RequiresCustomAuthService : Service
    {
        public RequiresCustomAuthResponse Any(RequiresCustomAuthRequest request)
        {
            return new RequiresCustomAuthResponse { Result = request.RequestData };
        }
    }
}
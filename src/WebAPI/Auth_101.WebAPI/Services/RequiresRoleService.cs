using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [RequiredRole("TheRole")]
    public class RequiresRoleService : Service
    {
        public object Any(RequiresRoleRequest request)
        {
            return new RequiresRoleResponse { Result = request.RequestData };
        }
    }
}
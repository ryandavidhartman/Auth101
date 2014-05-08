using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [RequiresAnyRole("TheRole", "TheRole2")]
    public class RequiresAnyRoleService : Service
    {
        public object Any(RequiresAnyRoleRequest request)
        {
            return new RequiresAnyRoleResponse { Result = request.Roles };
        }
    }
}
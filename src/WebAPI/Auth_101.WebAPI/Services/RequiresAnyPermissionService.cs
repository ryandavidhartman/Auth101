using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [RequiresAnyPermission("ThePermission", "ThePermission2")]
    public class RequiresAnyPermissionService : Service
    {
        public RequiresAnyPermissionResponse Any(RequiresAnyPermissionRequest request)
        {
            return new RequiresAnyPermissionResponse { Result = request.RequestData };
        }
    }
}
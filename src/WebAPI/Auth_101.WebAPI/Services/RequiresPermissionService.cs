using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [RequiredPermission("ThePermission")]
    public class RequiresPermissionService : Service
    {
        public RequiresPermissionResponse Any(RequiresPermissionRequest request)
        {
            return new RequiresPermissionResponse { Result = request.RequestData };
        }
    }
}
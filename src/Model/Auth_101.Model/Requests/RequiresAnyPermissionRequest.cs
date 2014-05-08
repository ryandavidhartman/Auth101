using System.Collections.Generic;
using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresAnyPermissionRequest")]
    public class RequiresAnyPermissionRequest : IReturn<RequiresAnyPermissionResponse>
    {
        public List<string> Permissions { get; set; }

        public RequiresAnyPermissionRequest()
        {
            Permissions = new List<string>();
        }
    }
}

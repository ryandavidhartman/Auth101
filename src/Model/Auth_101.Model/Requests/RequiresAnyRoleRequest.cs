using System.Collections.Generic;
using ServiceStack;


namespace Auth_101.Model.Requests
{
    [Route("/RequiresAnyRoleRequest")]
    public class RequiresAnyRoleRequest : IReturn<RequiresAnyRoleResponse>
    {
        public List<string> Roles { get; set; }

        public RequiresAnyRoleRequest()
        {
            Roles = new List<string>();
        }
    }
}

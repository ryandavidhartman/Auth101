using System.Collections.Generic;
using ServiceStack;

namespace Auth_101.Model.Requests
{
    public class RequiresAnyRoleResponse : IHasResponseStatus
    {
        public List<string> Result { get; set; }

        public ResponseStatus ResponseStatus { get; set; }

        public RequiresAnyRoleResponse()
        {
            Result = new List<string>();
        }
    }
}

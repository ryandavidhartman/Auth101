using System.Collections.Generic;
using ServiceStack;

namespace Auth_101.Model.Requests
{
    public class RequiresAnyPermissionResponse : IHasResponseStatus
    {
        public string Result { get; set; }
        
        public ResponseStatus ResponseStatus { get; set; }
    }
}

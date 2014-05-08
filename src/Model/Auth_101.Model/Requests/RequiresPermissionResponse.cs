using ServiceStack;

namespace Auth_101.Model.Requests
{
    public class RequiresPermissionResponse : IHasResponseStatus
    {
        public string Result { get; set; }

        public ResponseStatus ResponseStatus { get; set; }
    }
}

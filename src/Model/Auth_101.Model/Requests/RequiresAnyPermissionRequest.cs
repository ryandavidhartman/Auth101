using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresAnyPermissionRequest")]
    public class RequiresAnyPermissionRequest : IReturn<RequiresAnyPermissionResponse>
    {
        public string RequestData { get; set; }
    }
}

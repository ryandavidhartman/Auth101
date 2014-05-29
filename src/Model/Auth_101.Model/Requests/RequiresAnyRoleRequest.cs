using ServiceStack;


namespace Auth_101.Model.Requests
{
    [Route("/RequiresAnyRoleRequest")]
    public class RequiresAnyRoleRequest : IReturn<RequiresAnyRoleResponse>
    {
        public string RequestData { get; set; }
    }
}

using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/SecuredRequest")]
    public class SecuredRequest : IReturn<SecuredResponse>
    {
        public string Name { get; set; }
    }
}

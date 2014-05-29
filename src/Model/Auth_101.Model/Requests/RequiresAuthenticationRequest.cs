using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresAuthenticationRequest")]
    public class RequiresAuthenticationRequest : IReturn<RequiresAuthenticationResponse>
    {
        public string RequestData { get; set; }
    }
}

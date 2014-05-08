using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresCustomAuthRequest")]
    public class RequiresCustomAuthRequest : IReturn<RequiresCustomAuthResponse>
    {
        public string Name { get; set; }
    }
}

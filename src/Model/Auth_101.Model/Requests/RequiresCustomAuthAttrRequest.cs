using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresCustomAuthAttrRequest")]
    public class RequiresCustomAuthAttrRequest : IReturn<RequiresCustomAuthAttrResponse>
    {
        public string Name { get; set; }
    }
}

namespace UnitTests
{
    public class AuthTestsWithinVirtualDirectory : AuthTests
    {
        protected override string VirtualDirectory { get { return "somevirtualdirectory"; } }
        protected override string ListeningOn { get { return "http://localhost:1337/" + VirtualDirectory + "/"; } }
        protected override string WebHostUrl { get { return "http://mydomain.com/" + VirtualDirectory; } }
    }
}

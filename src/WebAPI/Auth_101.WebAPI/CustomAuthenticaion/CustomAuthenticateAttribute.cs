using ServiceStack;
using ServiceStack.Web;

namespace Auth_101.WebAPI.CustomAuthenticaion
{
    public class CustomAuthenticateAttribute : AuthenticateAttribute
    {
        public override void Execute(IRequest req, IResponse res, object requestDto)
        {
            //Need to run SessionFeature filter since its not executed before this attribute (Priority -100)
            SessionFeature.AddSessionIdToRequestFilter(req, res, null); //Required to get req.GetSessionId()

            req.Items["TriedMyOwnAuthFirst"] = true; // let's simulate some sort of auth _before_ relaying to base class.

            base.Execute(req, res, requestDto);
        }
    }
}
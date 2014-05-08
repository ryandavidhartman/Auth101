using System;
using ServiceStack;
using ServiceStack.Auth;

namespace Auth_101.WebAPI.CustomAuthenticaion
{
    public class CustomAuthProvider : AuthProvider
    {
        public CustomAuthProvider()
        {
            Provider = "custom";
        }

        public override bool IsAuthorized(IAuthSession session, IAuthTokens tokens, Authenticate request = null)
        {
            return false;
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {
            throw new NotImplementedException();
        }
    }
}
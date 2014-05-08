using System.Collections.Generic;
using Auth_101.Model.Constants;
using ServiceStack;
using ServiceStack.Auth;

namespace Auth_101.WebAPI.CustomAuthenticaion
{
    public class CustomUserSession : AuthUserSession
    {
        public override void OnAuthenticated(IServiceBase authService, IAuthSession session, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            if (session.UserName == SystemConstants.UserNameWithSessionRedirect)
                session.ReferrerUrl = SystemConstants.SessionRedirectUrl;
        }
    }
}
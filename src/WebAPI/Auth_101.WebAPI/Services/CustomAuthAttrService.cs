using System;
using Auth_101.Model.Requests;
using Auth_101.WebAPI.CustomAuthenticaion;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [CustomAuthenticate]
    public class CustomAuthAttrService : Service
    {
        public RequiresCustomAuthAttrResponse Any(RequiresCustomAuthAttrRequest request)
        {
            if (!Request.Items.ContainsKey("TriedMyOwnAuthFirst"))
                throw new InvalidOperationException("TriedMyOwnAuthFirst not present.");

            return new RequiresCustomAuthAttrResponse { Result = request.Name };
        }
    }
}
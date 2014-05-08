using System;
using System.Collections.Generic;
using Auth_101.Model.Constants;
using Auth_101.WebAPI.CustomAuthenticaion;
using Auth_101.WebAPI.Services;
using Funq;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.Caching;

namespace Auth_101.WebAPI
{
    public class AuthAppHostHttpListener : AppHostHttpListenerBase
    {
        private readonly string _webHostUrl;
        private readonly Action<Container> _configureFn;
        private InMemoryAuthRepository _userRep;

        public AuthAppHostHttpListener(string webHostUrl, Action<Container> configureFn = null)
            : base("Validation Tests", typeof(CustomerService).Assembly)
        {
            _webHostUrl = webHostUrl;
            _configureFn = configureFn;
        }

        public override void Configure(Container container)
        {
            SetConfig(new HostConfig { WebHostUrl = _webHostUrl });

            Plugins.Add(new AuthFeature(() => new CustomUserSession(),
                new IAuthProvider[] { //Www-Authenticate should contain basic auth, therefore register this provider first
                    new BasicAuthProvider(), //Sign-in with Basic Auth
                    new CredentialsAuthProvider(), //HTML Form post of UserName/Password credentials
                    new CustomAuthProvider()
                }, "~/" + SystemConstants.LoginUrl));

            container.Register(new MemoryCacheClient());
            _userRep = new InMemoryAuthRepository();
            container.Register<IAuthRepository>(_userRep);

            if (_configureFn != null)
            {
                _configureFn(container);
            }

            CreateUser(1, SystemConstants.UserName, null, SystemConstants.Password, new List<string> { "TheRole" }, new List<string> { "ThePermission" });
            CreateUser(2, SystemConstants.UserNameWithSessionRedirect, null, SystemConstants.PasswordForSessionRedirect);
            CreateUser(3, null, SystemConstants.EmailBasedUsername, SystemConstants.PasswordForEmailBasedAccount);
        }

        private void CreateUser(int id, string username, string email, string password, List<string> roles = null, List<string> permissions = null)
        {
            string hash;
            string salt;
            new SaltedHash().GetHashAndSaltString(password, out hash, out salt);

            _userRep.CreateUserAuth(new UserAuth
            {
                Id = id,
                DisplayName = "DisplayName",
                Email = email ?? "as@if{0}.com".Fmt(id),
                UserName = username,
                FirstName = "FirstName",
                LastName = "LastName",
                PasswordHash = hash,
                Salt = salt,
                Roles = roles,
                Permissions = permissions
            }, password);
        }

        protected override void Dispose(bool disposing)
        {
            // Needed so that when the derived class tests run the same users can be added again.
            _userRep.Clear();
            base.Dispose(disposing);
        }
    }
}
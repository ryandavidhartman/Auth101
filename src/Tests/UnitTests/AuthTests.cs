using System;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Auth_101.Model.Constants;
using Auth_101.Model.Requests;
using Auth_101.WebAPI;
using Auth_101.WebAPI.Clients;
using Funq;
using NUnit.Framework;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.Text; 

namespace UnitTests
{
    public class AuthTests
    {
        protected virtual string VirtualDirectory
        {
            get { return ""; }
        }

        protected virtual string ListeningOn
        {
            get { return "http://localhost:1337/"; }
        }

        protected virtual string WebHostUrl
        {
            get { return "http://mydomain.com"; }
        }

        private AuthAppHostHttpListener _appHost;

        [TestFixtureSetUp]
        public void OnTestFixtureSetUp()
        {
            _appHost = new AuthAppHostHttpListener(WebHostUrl, Configure);
            _appHost.Init();
            _appHost.Start(ListeningOn);
        }

        [TestFixtureTearDown]
        public void OnTestFixtureTearDown()
        {
            _appHost.Dispose();
        }

        public virtual void Configure(Container container)
        {
        }


        private IServiceClient GetClient()
        {
            return new JsonServiceClient(ListeningOn);
        }

        private IServiceClient GetHtmlClient()
        {
            return new HtmlServiceClient(ListeningOn) {BaseUri = ListeningOn};
        }

        private IServiceClient GetClientWithUserPassword()
        {
            return new JsonServiceClient(ListeningOn)
            {
                UserName = SystemConstants.UserName,
                Password = SystemConstants.Password
            };
        }

        [Test]
        public void no_credentials_throws_unauthorized()
        {
            var client = GetClient();
            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<SecuredResponse>(request));

            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void Authenticate_attribute_respects_provider()
        {
            var client = GetClient();
            var authResponse = client.Send(new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = "user",
                Password = "p@55word",
                RememberMe = true,
            });

            Assert.IsNull(authResponse.ResponseStatus.Errors);
            Assert.IsNull(authResponse.ResponseStatus.ErrorCode);
            Assert.IsFalse(authResponse.ResponseStatus.IsErrorResponse());


            var request = new RequiresCustomAuthRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresCustomAuthResponse>(request));

            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void PostFile_with_no_Credentials_throws_UnAuthorized()
        {
            var client = GetClient();
            var uploadFile = new FileInfo("~/TestExistingDir/upload.html".MapProjectPath());
            var error = Assert.Throws<WebServiceException>(() =>
                client.PostFile<SecuredFileUploadResponse>(ListeningOn + "/SecuredFileUploadRequest", uploadFile, MimeTypes.GetMimeType(uploadFile.Name)));

            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void PostFile_does_work_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            var uploadFile = new FileInfo("~/TestExistingDir/upload.html".MapProjectPath());

            var expectedContents = new StreamReader(uploadFile.OpenRead()).ReadToEnd();
            var response = client.PostFile<SecuredFileUploadResponse>(ListeningOn + "/SecuredFileUploadRequest", uploadFile, MimeTypes.GetMimeType(uploadFile.Name));
            Assert.That(response.FileName, Is.EqualTo(uploadFile.Name));
            Assert.That(response.ContentLength, Is.EqualTo(uploadFile.Length));
            Assert.That(response.Contents, Is.EqualTo(expectedContents));
        }

        [Test]
        public void PostFileWithRequest_does_work_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            var request = new SecuredFileUploadRequest {CustomerId = 123, CustomerName = "Foo"};
            var uploadFile = new FileInfo("~/TestExistingDir/upload.html".MapProjectPath());

            var expectedContents = new StreamReader(uploadFile.OpenRead()).ReadToEnd();
            var response = client.PostFileWithRequest<SecuredFileUploadResponse>(ListeningOn + "/SecuredFileUploadRequest", uploadFile, request);
            Assert.That(response.FileName, Is.EqualTo(uploadFile.Name));
            Assert.That(response.ContentLength, Is.EqualTo(uploadFile.Length));
            Assert.That(response.Contents, Is.EqualTo(expectedContents));
            Assert.That(response.CustomerName, Is.EqualTo("Foo"));
            Assert.That(response.CustomerId, Is.EqualTo(123));
        }

        [Test]
        public void does_work_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<SecuredResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void does_always_send_BasicAuth()
        {
            var client = (ServiceClientBase) GetClientWithUserPassword();
            client.AlwaysSendBasicAuthHeader = true;
            client.RequestFilter = req =>
            {
                bool hasAuthentication = false;
                foreach (var key in req.Headers.Keys)
                {
                    if (key.ToString() == "Authorization")
                        hasAuthentication = true;
                }
                Assert.IsTrue(hasAuthentication);
            };

            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<SecuredResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void does_work_with_CredentailsAuth()
        {
            var client = GetClient();

            var authResponse = client.Send(new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = "user",
                Password = "p@55word",
                RememberMe = true,
            });

            authResponse.PrintDump();

            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<SecuredResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public async Task does_work_with_CredentailsAuth_Async()
        {
            var client = GetClient();

            var request = new SecuredRequest {Name = "test"};
            var authResponse = await client.SendAsync<AuthenticateResponse>(
                new Authenticate
                {
                    provider = CredentialsAuthProvider.Name,
                    UserName = "user",
                    Password = "p@55word",
                    RememberMe = true,
                });

            authResponse.PrintDump();

            var response = await client.SendAsync<SecuredResponse>(request);

            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void can_call_RequiredRole_service_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            var request = new RequiresRoleRequest {RequestData = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<RequiresRoleResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.RequestData));
        }

        [Test]
        public void RequiredRole_service_returns_unauthorized_if_no_basic_auth_header_exists()
        {
            var client = GetClient();
            var request = new RequiresRoleRequest {RequestData = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresRoleResponse>(request));
            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void RequiredRole_service_returns_forbidden_if_basic_auth_header_exists()
        {
            var client = GetClient();
            ((ServiceClientBase) client).UserName = SystemConstants.EmailBasedUsername;
            ((ServiceClientBase) client).Password = SystemConstants.PasswordForEmailBasedAccount;

            var request = new RequiresRoleRequest {RequestData = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresRoleResponse>(request));
            Assert.AreEqual((int) HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual("Invalid Role", error.StatusDescription);
            Assert.AreEqual("Invalid Role", error.ErrorCode);
        }

        [Test]
        public void can_call_RequiredPermission_service_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            var request = new RequiresPermissionRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<RequiresPermissionResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void RequiredPermission_service_returns_unauthorized_if_no_basic_auth_header_exists()
        {
            var client = GetClient();
            var request = new RequiresPermissionRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresPermissionResponse>(request));
            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void RequiredPermission_service_returns_forbidden_if_basic_auth_header_exists()
        {
            var client = GetClient();
            ((ServiceClientBase) client).UserName = SystemConstants.EmailBasedUsername;
            ((ServiceClientBase) client).Password = SystemConstants.PasswordForEmailBasedAccount;

            var request = new RequiresPermissionRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresPermissionResponse>(request));

            Assert.AreEqual((int) HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual("Invalid Permission", error.StatusDescription);
            Assert.AreEqual("Invalid Permission", error.ErrorCode);
        }

        [Test]
        public void does_work_with_CredentailsAuth_Multiple_Times()
        {
            var client = GetClient();

            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var authResponse = client.Send<AuthenticateResponse>(new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = "user",
                Password = "p@55word",
                RememberMe = true,
            });

            Console.WriteLine(authResponse.Dump());

            for (int i = 0; i < 500; i++)
            {
                var request = new SecuredRequest {Name = "test"};
                // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
                var response = client.Send<SecuredResponse>(request);
                Assert.That(response.Result, Is.EqualTo(request.Name));
                Console.WriteLine("loop : {0}", i);
            }
        }

        [Test]
        public void exceptions_thrown_are_received_by_client_when_AlwaysSendBasicAuthHeader_is_false()
        {
            var client = (IRestClient) GetClientWithUserPassword();
            ((ServiceClientBase) client).AlwaysSendBasicAuthHeader = false;
            var error = Assert.Throws<WebServiceException>(() => client.Get<SecuredResponse>("/SecuredRequest"));

            Assert.AreEqual("unicorn nuggets", error.ErrorMessage);
            Assert.AreEqual((int) HttpStatusCode.BadRequest, error.StatusCode);
            Assert.AreEqual("ArgumentException", error.StatusDescription);
            Assert.AreEqual("ArgumentException", error.ErrorCode);
        }

        [Test]
        public void exceptions_thrown_are_received_by_client_when_AlwaysSendBasicAuthHeader_is_true()
        {
            var client = (IRestClient) GetClientWithUserPassword();
            ((ServiceClientBase) client).AlwaysSendBasicAuthHeader = true;
            var error = Assert.Throws<WebServiceException>(() => client.Get<SecuredResponse>("/SecuredRequest"));

            Assert.AreEqual("unicorn nuggets", error.ErrorMessage);
            Assert.AreEqual((int) HttpStatusCode.BadRequest, error.StatusCode);
            Assert.AreEqual("ArgumentException", error.StatusDescription);
            Assert.AreEqual("ArgumentException", error.ErrorCode);
        }

        [Test]
        public void html_clients_receive_redirect_to_login_page_when_accessing_unauthenticated()
        {
            var client = (ServiceClientBase) GetHtmlClient();
            client.AllowAutoRedirect = false;
            string lastResponseLocationHeader = null;
            client.ResponseFilter = response => { lastResponseLocationHeader = response.Headers["Location"]; };

            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            client.Send<SecuredResponse>(request);

            var locationUri = new Uri(lastResponseLocationHeader);
            var loginPath = "/".CombineWith(VirtualDirectory).CombineWith(SystemConstants.LoginUrl);
            Assert.That(locationUri.AbsolutePath, Is.EqualTo(loginPath).IgnoreCase);
        }

        [Test]
        public void html_clients_receive_secured_url_attempt_in_login_page_redirect_query_string()
        {
            var client = (ServiceClientBase) GetHtmlClient();
            client.AllowAutoRedirect = false;
            string lastResponseLocationHeader = null;
            client.ResponseFilter = response => { lastResponseLocationHeader = response.Headers["Location"]; };

            var request = new SecuredRequest {Name = "test"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            client.Send<SecuredResponse>(request);

            var locationUri = new Uri(lastResponseLocationHeader);
            var queryString = HttpUtility.ParseQueryString(locationUri.Query);
            var redirectQueryString = queryString["redirect"];
            var redirectUri = new Uri(redirectQueryString);

            // Should contain the url attempted to access before the redirect to the login page.
            var securedPath = "/".CombineWith(VirtualDirectory).CombineWith("securedrequest");
            Assert.That(redirectUri.AbsolutePath, Is.EqualTo(securedPath).IgnoreCase);
            // The url should also obey the WebHostUrl setting for the domain.
            var redirectSchemeAndHost = redirectUri.Scheme + "://" + redirectUri.Authority;
            var webHostUri = new Uri(WebHostUrl);
            var webHostSchemeAndHost = webHostUri.Scheme + "://" + webHostUri.Authority;
            Assert.That(redirectSchemeAndHost, Is.EqualTo(webHostSchemeAndHost).IgnoreCase);
        }

        [Test]
        public void html_clients_receive_secured_url_including_query_string_within_login_page_redirect_query_string()
        {
            var client = (ServiceClientBase) GetHtmlClient();
            client.AllowAutoRedirect = false;
            string lastResponseLocationHeader = null;
            client.ResponseFilter = response => { lastResponseLocationHeader = response.Headers["Location"]; };

            var request = new SecuredRequest {Name = "test"};
            // Perform a GET so that the Name DTO field is encoded as query string.
            client.Get(request);

            var locationUri = new Uri(lastResponseLocationHeader);
            var locationUriQueryString = HttpUtility.ParseQueryString(locationUri.Query);
            var redirectQueryItem = locationUriQueryString["redirect"];
            var redirectUri = new Uri(redirectQueryItem);

            // Should contain the url attempted to access before the redirect to the login page,
            // including the 'Name=test' query string.
            var redirectUriQueryString = HttpUtility.ParseQueryString(redirectUri.Query);
            Assert.That(redirectUriQueryString.AllKeys, Contains.Item("name"));
            Assert.That(redirectUriQueryString["name"], Is.EqualTo("test"));
        }

        [Test]
        public void html_clients_receive_session_ReferrerUrl_on_successful_authentication()
        {
            var client = (ServiceClientBase) GetHtmlClient();
            client.AllowAutoRedirect = false;
            string lastResponseLocationHeader = null;
            client.ResponseFilter = response => { lastResponseLocationHeader = response.Headers["Location"]; };

            client.Send(new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = SystemConstants.UserNameWithSessionRedirect,
                Password = SystemConstants.PasswordForSessionRedirect,
                RememberMe = true,
            });

            Assert.That(lastResponseLocationHeader, Is.EqualTo(SystemConstants.SessionRedirectUrl));
        }

        [Test]
        public void already_authenticated_session_returns_correct_username()
        {
            var client = GetClient();

            var authRequest = new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = SystemConstants.UserName,
                Password = SystemConstants.Password,
                RememberMe = true,
            };
            var initialLoginResponse = client.Send(authRequest);
            Assert.IsFalse(initialLoginResponse.IsErrorResponse());
            Assert.AreEqual(SystemConstants.UserName, initialLoginResponse.UserName);

            var alreadyLogggedInResponse = client.Send(authRequest);
            Assert.IsFalse(alreadyLogggedInResponse.IsErrorResponse());
            Assert.AreEqual(SystemConstants.UserName, alreadyLogggedInResponse.UserName);
            Assert.AreEqual(initialLoginResponse.SessionId, alreadyLogggedInResponse.SessionId);
        }

        [Test]
        public void authResponse_returns_email_as_username_if_user_registered_with_email()
        {
            var client = GetClient();

            var authRequest = new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = SystemConstants.EmailBasedUsername,
                Password = SystemConstants.PasswordForEmailBasedAccount,
                RememberMe = true,
            };
            var authResponse = client.Send(authRequest);

            Assert.That(authResponse.UserName, Is.EqualTo(SystemConstants.EmailBasedUsername));
        }

        [Test]
        public void already_authenticated_session_returns_correct_username_when_user_registered_with_email()
        {
            var client = GetClient();

            var authRequest = new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = SystemConstants.EmailBasedUsername,
                Password = SystemConstants.PasswordForEmailBasedAccount,
                RememberMe = true,
            };
            var initialLoginResponse = client.Send(authRequest);
            var alreadyLogggedInResponse = client.Send(authRequest);

            Assert.That(initialLoginResponse.UserName, Is.EqualTo(SystemConstants.EmailBasedUsername));
            Assert.That(alreadyLogggedInResponse.UserName, Is.EqualTo(SystemConstants.EmailBasedUsername));
        }

        [Test]
        public void can_call_RequiresAnyRole_service_with_BasicAuth()
        {
            var client = GetClientWithUserPassword();
            
            var request = new RequiresAnyRoleRequest {RequestData = "some data"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<RequiresAnyRoleResponse>(request);
            Assert.AreEqual(response.Result, request.RequestData);
        }

        [Test]
        public void RequiresAnyRole_service_returns_unauthorized_if_no_basic_auth_header_exists()
        {
            var client = GetClient();
           
            var request = new RequiresAnyRoleRequest {RequestData = "some data"};
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresAnyRoleRequest>(request));

            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void RequiresAnyRole_service_returns_forbidden_if_basic_auth_header_exists()
        {
            var client = GetClient();
            ((ServiceClientBase) client).UserName = SystemConstants.EmailBasedUsername;
            ((ServiceClientBase) client).Password = SystemConstants.PasswordForEmailBasedAccount;

           
            var request = new RequiresAnyRoleRequest {RequestData = "some data"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresAnyRoleResponse>(request));
            Assert.AreEqual((int) HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual("Invalid Role", error.StatusDescription);
            Assert.AreEqual("Invalid Role", error.ErrorCode);
        }

        [Test]
        public void can_call_RequiresAnyPermission_service_with_basic_auth()
        {
            var client = GetClientWithUserPassword();
            
            var request = new RequiresAnyPermissionRequest {RequestData = "some data"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<RequiresAnyPermissionResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.RequestData));
        }

        [Test]
        public void RequiresAnyPermission_service_returns_unauthorized_if_no_basic_auth_header_exists()
        {
            var client = GetClient();
            
            var request = new RequiresAnyPermissionRequest {RequestData = "some data"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresAnyPermissionResponse>(request));

            Assert.AreEqual((int) HttpStatusCode.Unauthorized, error.StatusCode);
            Assert.AreEqual("Unauthorized", error.StatusDescription);
            Assert.AreEqual("Unauthorized", error.ErrorCode);
        }

        [Test]
        public void RequiresAnyPermission_service_returns_forbidden_if_basic_auth_header_exists()
        {
            var client = GetClient();

            // This inserts the basic auth info
            ((ServiceClientBase) client).UserName = SystemConstants.EmailBasedUsername;
            ((ServiceClientBase) client).Password = SystemConstants.PasswordForEmailBasedAccount;

           
            var request = new RequiresAnyPermissionRequest {RequestData = "some data"};
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var error = Assert.Throws<WebServiceException>(() => client.Send<RequiresAnyPermissionResponse>(request));

            Assert.AreEqual((int) HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual("Invalid Permission", error.StatusDescription);
            Assert.AreEqual("Invalid Permission", error.ErrorCode);
        }

        [Test]
        public void calling_add_session_id_to_request_from_a_custom_auth_attribute_does_not_duplicate_session_cookies()
        {
            WebHeaderCollection headers = null;
            var client = GetClientWithUserPassword();
            ((ServiceClientBase) client).AlwaysSendBasicAuthHeader = true;
            ((ServiceClientBase) client).ResponseFilter = x => headers = x.Headers;
            // ReSharper disable once RedundantTypeArgumentsOfMethod  (Parameter type added for clarity only)
            var response = client.Send<RequiresCustomAuthAttrResponse>(new RequiresCustomAuthAttrRequest {Name = "Hi You"});
            Assert.That(response.Result, Is.EqualTo("Hi You"));
            Assert.That(
                Regex.Matches(headers["Set-Cookie"], "ss-id=").Count,
                Is.EqualTo(1)
                );
        }


        [Test]
        public void meaningful_exception_for_unknown_auth_header()
        {
            //http://dotnetinside.com/en/type/ServiceStack.Client/AuthenticationInfo/4.0.20.0
            //http://en.wikipedia.org/wiki/Basic_access_authentication

            var good1 = new AuthenticationInfo("Basic realm=\"registrar\"");
            Assert.IsNotNull(good1);

            const string header = "Digest username=\"admin\"," +
                                  "realm=\"The batcave\"," +
                                  "nonce=\"49938e61ccaa\"," +
                                  "uri=\"/\"," +
                                  "response=\"98ccab4542f284c00a79b5957baaff23\"," +
                                  "opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\"," +
                                  "qop=auth, nc=00000001," +
                                  "cnonce=\"8d1b34edb475994b\"";


            var good2 = new AuthenticationInfo(header);
            Assert.IsNotNull(good2);


            var error = Assert.Throws<AuthenticationException>(() => new AuthenticationInfo("Negotiate,NTLM"));
            Assert.AreEqual("Authentication header not supported: Negotiate,NTLM", error.Message);
        }

        [Test]
        public void can_logout_using_CredentailsAuthProvider()
        {
            Assert.That(AuthenticateService.LogoutAction, Is.EqualTo("logout"));


            var client = GetClient();

            var authResponse = client.Send(new Authenticate
            {
                provider = CredentialsAuthProvider.Name,
                UserName = "user",
                Password = "p@55word",
                RememberMe = true,
            });

            Assert.That(authResponse.SessionId, Is.Not.Null);

            var logoutResponse = client.Get<AuthenticateResponse>("/auth/logout");

            Assert.That(logoutResponse.ResponseStatus.ErrorCode, Is.Null);

            logoutResponse = client.Send(new Authenticate
            {
                provider = AuthenticateService.LogoutAction,
            });

            Assert.That(logoutResponse.ResponseStatus.ErrorCode, Is.Null);
        }
    }
}
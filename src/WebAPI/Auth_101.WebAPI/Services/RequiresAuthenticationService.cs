using System;
using System.IO;
using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [Authenticate]
    public class RequiresAuthenticationService : Service
    {
        public object Post(RequiresAuthenticationRequest request)
        {
            return new RequiresAuthenticationResponse { Result = request.RequestData };
        }

        public object Get(RequiresAuthenticationRequest request)
        {
            throw new ArgumentException("unicorn nuggets");
        }

        public object Post(SecuredFileUploadRequest request)
        {
            var file = Request.Files[0];
            return new SecuredFileUploadResponse
            {
                FileName = file.FileName,
                ContentLength = file.ContentLength,
                ContentType = file.ContentType,
                Contents = new StreamReader(file.InputStream).ReadToEnd(),
                CustomerId = request.CustomerId,
                CustomerName = request.CustomerName
            };
        }
    }
}
using System;
using System.IO;
using Auth_101.Model.Requests;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    [Authenticate]
    public class SecuredService : Service
    {
        public object Post(SecuredRequest request)
        {
            return new SecuredResponse { Result = request.Name };
        }

        public object Get(SecuredRequest request)
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
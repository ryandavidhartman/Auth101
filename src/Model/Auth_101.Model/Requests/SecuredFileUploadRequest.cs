using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/SecuredFileUploadRequest")]
    public class SecuredFileUploadRequest : IReturn<SecuredFileUploadResponse>
    {
        public int CustomerId { get; set; }
        public string CustomerName { get; set; }
    }
}

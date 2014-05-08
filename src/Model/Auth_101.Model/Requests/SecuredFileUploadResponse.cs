using System;
using System.Runtime.Serialization;
using ServiceStack;

namespace Auth_101.Model.Requests
{

    [DataContract]
    public class SecuredFileUploadResponse : IHasResponseStatus
    {
        [DataMember]
        public string FileName { get; set; }

        [DataMember]
        public long ContentLength { get; set; }

        [DataMember]
        public string ContentType { get; set; }

        [DataMember]
        public string Contents { get; set; }

        [DataMember]
        public ResponseStatus ResponseStatus { get; set; }

        [DataMember]
        public string CustomerName { get; set; }

        [DataMember]
        public int CustomerId { get; set; }

        [DataMember]
        public DateTime CreatedDate { get; set; }
    }

}

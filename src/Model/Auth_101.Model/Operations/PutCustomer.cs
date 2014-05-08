using Auth_101.Model.Data;
using MessagingServiceUtilities.Interfaces;

namespace Auth_101.Model.Operations
{
    public class PutCustomer : IMessagingPutDto<Customer>
    {
        public Customer Body { get; set; }
    }
}

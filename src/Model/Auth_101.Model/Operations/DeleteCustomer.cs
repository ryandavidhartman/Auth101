using Auth_101.Model.Data;
using MessagingServiceUtilities.Interfaces;

namespace Auth_101.Model.Operations
{
    public class DeleteCustomer : IMessagingDeleteDto<Customer>
    {
        public Customer Body { get; set; }
    }
}

using RESTServiceUtilities.Interfaces;
using ServiceStack;
using ServiceStack.DataAnnotations;

namespace Auth_101.Model.Data
{
    [Api("Insert update or delete a Customer")]
    [Route("/customers", "POST")]
    [Route("/customers/{Id}", "PUT")]
    [Route("/customers/{Id}", "DELETE")]
    public class Customer : IReturn<Customer>, IData
    {
        [AutoIncrement]
        public long Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Company { get; set; }
        public decimal Discount { get; set; }
        public string Address { get; set; }
        public string Postcode { get; set; }
        public bool HasDiscount { get; set; }
    }
}
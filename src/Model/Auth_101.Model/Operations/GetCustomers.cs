using System.Collections.Generic;
using Auth_101.Model.Data;
using RESTServiceUtilities.Interfaces;
using ServiceStack;

namespace Auth_101.Model.Operations
{
    [Api("Return a List of Customers Resources")]
    [Route("/customers", "GET")]
    [Route("/customers/{Ids}", "GET")]
    public class GetCustomers : IReturn<List<Customer>>, IDatas
    {
        public List<long> Ids { get; set; }
    }
}

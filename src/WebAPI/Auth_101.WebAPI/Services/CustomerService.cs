using Auth_101.Model.Data;
using ServiceStack;

namespace Auth_101.WebAPI.Services
{
    public class CustomerService : Service
	{
		public object Get(Customer request)
		{
		    return request;
		}

		public object Post(Customer request)
		{
		    return request;
		}

		public object Put(Customer request)
		{
		    return request;
		}

		public void Delete(Customer request)
		{
		}
	}

}

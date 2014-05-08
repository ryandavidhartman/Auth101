﻿using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresRoleRequest")]
    public class RequiresRoleRequest : IReturn<RequiresRoleResponse>
    {
        public string Name { get; set; }
    }
}

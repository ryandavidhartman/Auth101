﻿
using ServiceStack;

namespace Auth_101.Model.Requests
{
    [Route("/RequiresPermissionsRequest")]
    public class RequiresPermissionRequest : IReturn<RequiresPermissionResponse>
    {
        public string Name { get; set; }
    }
}

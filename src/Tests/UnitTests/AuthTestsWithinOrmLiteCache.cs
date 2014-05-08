
using Funq;
using ServiceStack.Caching;
using ServiceStack.Data;
using ServiceStack.OrmLite;

namespace UnitTests
{
    public class AuthTestsWithinOrmLiteCache : AuthTests
    {
        protected override string VirtualDirectory { get { return "somevirtualdirectory"; } }
        protected override string ListeningOn { get { return "http://localhost:1337/" + VirtualDirectory + "/"; } }
        protected override string WebHostUrl { get { return "http://mydomain.com/" + VirtualDirectory; } }

        public override void Configure(Container container)
        {
            container.Register<IDbConnectionFactory>(c =>
                new OrmLiteConnectionFactory(":memory:", SqliteDialect.Provider));

            container.RegisterAs<OrmLiteCacheClient, ICacheClient>();
            container.Resolve<ICacheClient>().InitSchema();
        }
    }
}

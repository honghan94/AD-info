using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(MyProject.Startup))]

namespace MyProject
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

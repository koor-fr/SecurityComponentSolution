using KooR.SecurityComponent;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityComponentMock
{
    public class MockSecurityComponent
    {
        public MockSecurityComponent()
        {
            ISecurityManager securityManager = Substitute.For<ISecurityManager>();

            IUserManager userManager = Substitute.For<IUserManager>();
            userManager.CheckCredentials("root", "admin").Returns(new User( securityManager,1, "root", "admin" ) );

            IRoleManager roleManager = Substitute.For<IRoleManager>();

            securityManager.UserManager.Returns(userManager);
            securityManager.RoleManager.Returns(roleManager);

        }


    }
}

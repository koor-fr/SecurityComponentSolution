using KooR.SecurityComponent;
using KooR.SecurityComponent.Impl;
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Data.SqlClient;

namespace SecurityComponentTest
{
    [TestClass]
    public class SqlSecurityComponentTest
    {
        private const string connectionString = "Data Source = localhost; Initial Catalog = SecurityComponent; Integrated Security = True";
        private SqlConnection connection;

        [TestInitialize]
        public void SetUp()
        {
            connection = new SqlConnection(connectionString);
        }

        [TestCleanup]
        public void TearDown()
        {
            connection.Close();
        }

        [TestMethod]
        public void TestGoodLogin()
        {
            ISecurityManager securityManager = new SqlSecurityManager(connection);
            securityManager.OpenSession();
            IUserManager userManager = securityManager.UserManager;
            User user = userManager.CheckCredentials("root", "admin");
            securityManager.Close();

            Assert.AreEqual("root", user.Login);
            Assert.IsFalse(user.Disabled);
            Assert.AreEqual(0u, user.ConsecutiveErrors);
        }

        [TestMethod, ExpectedException(typeof(BadCredentialsException))]
        public void TestBadLogin()
        {
            ISecurityManager securityManager = new SqlSecurityManager(connection);
            securityManager.OpenSession();
            IUserManager userManager = securityManager.UserManager;
            User user = userManager.CheckCredentials("Johnny", "English");
            securityManager.Close();
        }

        [TestMethod]
        public void TempTest()
        {
            ISecurityManager securityManager = new SqlSecurityManager(connection);
            securityManager.OpenSession();
            IRoleManager roleManager = securityManager.RoleManager;

            Role role = roleManager.SelectRoleByName("demo");
            roleManager.DeleteRole();

            securityManager.Close();
        }

    }
}
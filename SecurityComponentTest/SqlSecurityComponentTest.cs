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
        [TestMethod, TestCategory("CI")]
        public void TestGoodLogin()
        {
            string connectionString = "Data Source = localhost; Initial Catalog = SecurityComponent; Integrated Security = True";
            using (SqlConnection connection = new SqlConnection(connectionString))
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

        }
    }
}

using System;
using System.Reflection;
using AnotherComponentTest.ManualMock;
using KooR.AnotherComponent;
using KooR.SecurityComponent;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace KooR.AnotherComponentTest
{
    class Demo
    {
        private int aField = 123;
    }


    [TestClass]
    public class UnitTest1
    {

        [TestMethod]
        public void TestWhiteBox()
        {
            // --- On lance un test ---
            Demo d = new Demo();

            // --- On vérifie l'etat interne ---
            Type metadata = d.GetType();
            FieldInfo probe = metadata.GetField("aField", BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.AreEqual(123, probe.GetValue(d));
        }

        [TestMethod, TestCategory("CI")]
        public void TestDoSomething_ManualMock()
        {
            ISecurityManager securityManager = new SecurityManagerMock();

            // --- Set up the test ---
            Another component = new Another();
            component.SecurityManager = securityManager;
            component.DoSomething();

            // --- Verify some results ---
            Assert.IsTrue(component.State);
        }

        [TestMethod, TestCategory("CI")]
        public void TestDoSomething_AutoMock()
        {
            // --- Create a Mock with NSubstitute (http://nsubstitute.github.io/) ---
            ISecurityManager securityManager = Substitute.For<ISecurityManager>();

            IUserManager userManager = Substitute.For<IUserManager>();
            userManager.CheckCredentials("root", "admin").Returns(new User(securityManager, 1, "root", "admin"));
            userManager.EncryptPassword("admin").Returns("admin");

            IRoleManager roleManager = Substitute.For<IRoleManager>();

            securityManager.UserManager.Returns(userManager);
            securityManager.RoleManager.Returns(roleManager);

            // --- Set up the test ---
            Another component = new Another();
            component.SecurityManager = securityManager;
            component.DoSomething();

            // --- Verify some results ---
            userManager.Received().CheckCredentials("root", "admin");
            userManager.DidNotReceive().GetUserById(Arg.Any<uint>());
            Assert.IsTrue(component.State);
        }
    }
}

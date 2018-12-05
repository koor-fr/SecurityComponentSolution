using System;
using System.Reflection;
using KooR.AnotherComponent;
using KooR.SecurityComponent;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace KooR.AnotherComponentTest
{


    [TestClass]
    public class UnitTest1
    {

        //[TestMethod]
        public void TestDoSomething_ManualMock()
        {
            // TODO: produce a manual mock and use it
            //ISecurityManager securityManager = new SecurityManagerMock();

            // --- Set up the test ---
            //Another component = new Another();
            //component.SecurityManager = securityManager;
            //component.DoSomething();

            // --- Verify some results ---
            //Assert.IsTrue(component.State);
        }
        
        //[TestMethod]
        public void TestDoSomething_AutoMock()
        {
            // --- Create a Mock with NSubstitute (http://nsubstitute.github.io/) ---
            // TODO: produce a mock 

            // --- Set up the test ---
            //Another component = new Another();
            //component.SecurityManager = securityManager;
            //component.DoSomething();

            // --- Verify some results ---
            // Check if CheckCredentials is called
            ///Assert.IsTrue(component.State);
        }
    }
}

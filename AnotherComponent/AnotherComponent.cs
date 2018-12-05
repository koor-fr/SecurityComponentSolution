using KooR.SecurityComponent;
using KooR.SecurityComponent.Impl;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KooR.AnotherComponent
{
    public class Another
    {
        private ISecurityManager securityManager;
        private bool state = false;

        public ISecurityManager SecurityManager
        {
            get { return this.securityManager; }
            set { this.securityManager = value ?? throw new NullReferenceException("securityManager cannot be null");  }
        }

        public bool State
        {
            get { return this.state; }
            set { this.state = value; }
        }

        public void DoSomething()
        {
            this.securityManager.OpenSession();
            IUserManager userManager = this.securityManager.UserManager;
            User user = userManager.CheckCredentials("root", "admin");
            Console.Out.WriteLine("DoSomething with " + user.Login);
            if (user.IsMemberOfRole("admin"))
            {
                this.state = true;
            }
            this.securityManager.Close();
        }

        static void Main(string[] args)
        {

            string connectionString = "Data Source = localhost; Initial Catalog = SecurityComponent; Integrated Security = True";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                Another component = new Another();
                ISecurityManager dependency = new SqlSecurityManager(connection);
                component.SecurityManager = dependency;
                component.DoSomething();
            }
           
        }
    }
}

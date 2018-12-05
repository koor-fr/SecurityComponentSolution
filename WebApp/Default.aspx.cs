using KooR.SecurityComponent;
using KooR.SecurityComponent.Impl;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace WebApp
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnConnect_Click(object sender, EventArgs e)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["WebApp"].ConnectionString;
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                try
                {
                    ISecurityManager securityManager = new SqlSecurityManager(connection);
                    securityManager.OpenSession();
                    IUserManager userManager = securityManager.UserManager;

                    string login = txtLogin.Text;
                    string password = txtPassword.Text;
                    User user = userManager.CheckCredentials(login, password);
                    securityManager.Close();
                    lblResult.Text = "Welcome " + txtLogin.Text;
                }
                catch ( BadCredentialsException )
                {
                    lblResult.Text = "Téki?";
                }
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KooR.SecurityComponent.Impl
{
    public class SqlSecurityManager : ISecurityManager
    {
        private SqlConnection connection;
        private bool initialyOpen = false;

        private readonly SqlUserManager userManager;
        private readonly SqlRoleManager roleManager;


        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="connection">A connection to the used Sql Server</param>
        public SqlSecurityManager( SqlConnection connection )
        {
            this.connection = connection ?? throw new System.Security.SecurityException("connection connot be null");
            userManager = new SqlUserManager(this);
            roleManager = new SqlRoleManager(this);
            Console.Out.WriteLine("Concrete SecurityManager instanciated");
        }

        public SqlConnection Connexion
        {
            get { return this.connection; }
        }

        /// <summary>
        ///     Open a session to the considered security service.
        /// </summary>
        /// <exception cref="SecurityManagerException">Thrown when connection to the security service cannot be established.</exception>
        public void OpenSession()
        {
            if ( this.connection.State == System.Data.ConnectionState.Open )
            {
                this.initialyOpen = true;
            }
            else
            {
                try
                {
                    this.connection.Open();
                }
                catch ( Exception exception )
                {
                    throw new SecurityManagerException("Can't establish connection to the rDBMS", exception);
                }
            }
        }

        /// <summary>
        ///     Close the session with the considered security service.
        ///     If the connection to the database was initially closed, the CloseSession method automatically closes the connection.
        ///     Otherwise, it will leave the connection to the database as is.
        /// </summary>
        /// <exception cref="SecurityManagerException">Thrown when connection to the security service cannot be closed.</exception>
        public void Close()
        {
            try
            {
                if (!this.initialyOpen) this.connection.Close();
            }
            catch (Exception exception)
            {
                throw new SecurityManagerException("Can't close connection to the rDBMS", exception);
            }


        }

        /// <summary>
        ///     Get the role manager associated to this security manager.
        ///     A role manager provided methods to manage roles.
        /// </summary>
        public IRoleManager RoleManager {
			get { return this.roleManager; }
		}

        /// <summary>
        ///     Get the user manager associated to this security manager.
        ///     A user manager provided methods to manage users.
        /// </summary>
        public IUserManager UserManager {
            get { return this.userManager; }
        }


        /*/// <summary>
        ///     Returns the next used primary key for the specified table and column.
        ///     Caution: the type of the specified column must be compatible with the int java type.
        /// </summary>
        /// <param name="tableName">The name of the considered table.</param>
        /// <param name="columnName">The name of the column that contains primary keys.</param>
        /// <returns>The next available value.</returns>
        /// <exception cref="SecurityManagerException">Thrown if a Sql error is generated.</exception>
        private uint GetNextAvailablePrimaryKey(string tableName, string columnName)
        {
            uint nextIdentifier = 0;

            try
            {
                string strSql = String.Format("SELECT max({0}) FROM {1}", columnName, tableName);
                using (SqlCommand command = new SqlCommand(strSql, this.connection))
                {
                    nextIdentifier = (uint) (int) command.ExecuteScalar();
                    return ++nextIdentifier;
                }
            }
            catch ( Exception  exception ) {
                throw new SecurityManagerException("Cannot compute next primary key", exception );
            }
        }*/


        private class SqlUserManager : IUserManager
        {
            private SqlSecurityManager securityManager;

            /// <summary>
            ///     Class constructor
            /// </summary>
            /// <param name="securityManager">The main security manager</param>
            public SqlUserManager( SqlSecurityManager securityManager )
            {
                this.securityManager = securityManager;
            }

            public User CheckCredentials( string userLogin, string userPassword ) {
	            try {
		            string userNewPassword = this.EncryptPassword(userPassword);

                    string strSql = "SELECT * FROM T_USERS WHERE Login like @login and Password like @password";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@login", userLogin);
                        command.Parameters.AddWithValue("@password", userNewPassword);

                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                uint identifier = (uint)reader.GetInt32(0);
                                uint connectionNumber = (uint)reader.GetInt32(3) + 1;
                                DateTime lastConnection = DateTime.Now;
                                uint consecutiveErrors = (uint)reader.GetInt32(5);
                                bool isDisabled = reader.GetBoolean(6);
                                string firstName = reader.IsDBNull(7) ? null : reader.GetString(7);
                                string lastName = reader.IsDBNull(8) ? null : reader.GetString(8);
                                string email = reader.IsDBNull(9) ? null : reader.GetString(9);

                                if (isDisabled) throw new AccountDisabledException("Account is disabled");
                                consecutiveErrors = 0;
                                reader.Close();

                                strSql = "UPDATE T_USERS SET ConnectionNumber=@connectionNumber, LastConnection=@lastConnection, ConsecutiveErrors=0 WHERE IdUser=@identifier";
                                using (SqlCommand command2 = new SqlCommand(strSql, this.securityManager.connection))
                                {
                                    command2.Parameters.AddWithValue("@connectionNumber", (int)connectionNumber);
                                    command2.Parameters.AddWithValue("@lastConnection", lastConnection);
                                    command2.Parameters.AddWithValue("@identifier", (int)identifier);
                                    command2.ExecuteNonQuery();
                                }

                                User user = new User(this.securityManager, identifier, userLogin, userNewPassword);
                                user.ConnectionNumber = connectionNumber;
                                user.LastConnection = lastConnection;
                                user.ConsecutiveErrors = consecutiveErrors;
                                user.Disabled = isDisabled;
                                user.FirstName = firstName;
                                user.LastName = lastName;
                                user.Email = email;

                                // Associated roles loading
                                IRoleManager roleManager = this.securityManager.RoleManager;
                                strSql = "SELECT tr.* FROM T_USER_ROLES tur INNER JOIN T_ROLES tr ON tur.idRole=tr.idRole WHERE IdUser=@identifier";
                                using (SqlCommand command2 = new SqlCommand(strSql, this.securityManager.connection))
                                {
                                    command2.Parameters.AddWithValue("@identifier", (int)identifier);
                                    using (SqlDataReader reader2 = command2.ExecuteReader())
                                    {
                                        while (reader2.Read())
                                        {
                                            Role role = new Role((uint)reader2.GetInt32(0), reader2.GetString(1));
                                            user.AddRole(role);
                                        }
                                    }
                                }

                                return user;
                            }
                        }
                    }
	            } catch ( AccountDisabledException exception ) {
		            throw exception;
	            } catch ( Exception exception ) {
		            throw new BadCredentialsException("Can't check credentials", exception);
                }

	            try {
		            string strSql = "SELECT * FROM T_USERS WHERE Login like @login";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@login", userLogin);
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                uint identifier = (uint)reader.GetInt32(0);
                                bool forceDisabling = reader.GetInt32(5) == 2;

                                strSql = "UPDATE T_USERS SET ConsecutiveError=ConsecutiveError+1, IsDisabled=@disabled WHERE IdUser=@identifier";
                                using (SqlCommand command2 = new SqlCommand(strSql, this.securityManager.connection))
                                {
                                    command2.Parameters.AddWithValue("@disabled", forceDisabling);
                                    command2.Parameters.AddWithValue("@identifier", identifier);
                                    command2.ExecuteNonQuery();
                                }

                                if (forceDisabling)
                                {
                                    throw new AccountDisabledException("Account is disabled");
                                }
                            }
                        }
		            }
	            } catch ( Exception exception ) {
		            throw new BadCredentialsException("Your identity is rejected", exception);
	            }

	            throw new BadCredentialsException( "Your identity is rejected" );
            }

            public User GetUserById(uint userId)
            {
	            // TODO
	            return null;
            }

            public User GetUserByLogin(string  login)
            {
                // TODO
                return null;
            }

            public List<User> GetUsersByRole(Role role)
            {
                // TODO
                return null;
            }

            public User InsertUser(string login, string password)
            {
                // TODO
                return null;
            }

            public void UpdateUser(User user)
            {
                // TODO
            }

            public void DeleteUser(User user)
            {
                // TODO
            }

            public string EncryptPassword( string clearPassword )
            {
	            return clearPassword;  	// TODO: finish encription
            }

        }

        private class SqlRoleManager : IRoleManager
        {
            private SqlSecurityManager securityManager;

            /// <summary>
            ///     Class constructor
            /// </summary>
            /// <param name="securityManager">The main security manager</param>
            public SqlRoleManager(SqlSecurityManager securityManager)
            {
                this.securityManager = securityManager;
            }

            public Role SelectRoleById(uint roleIdentifier)
            {
                try
                {
                    string strSql = "SELECT RoleName FROM T_ROLES WHERE IdRole=@roleIdentifier";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@roleIdentifier", roleIdentifier);
                        string roleName = (string)command.ExecuteScalar();
                        return new Role(roleIdentifier, roleName);
                    }
                }
                catch (Exception exception)
                {
                    throw new SecurityManagerException("Cannot select role for identifier " + roleIdentifier, exception);
                }
            }


            public Role SelectRoleByName(string roleName)
            {
                try
                {
                    string strSql = "SELECT idRole FROM T_ROLES WHERE roleName like @roleName";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@roleName", roleName);
                        int roleIdentifier = (int) command.ExecuteScalar();
                        return new Role((uint)roleIdentifier, roleName);
                    }
                }
                catch (Exception exception)
                {
                    throw new SecurityManagerException("Cannot select role for name " + roleName, exception);
                }
            }


            public Role InsertRole(string roleName)
            {
                try
                {
                    string strSql = "SELECT IdRole FROM T_ROLES WHERE RoleName like @roleName";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@roleName", roleName);
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            if (reader.Read()) throw new SecurityManagerException("Role " + roleName + " already registered");
                        }
                        
                    }
                }
                catch ( Exception exception ) 
                {
                    throw new SecurityManagerException("Can't check the role existance: " + roleName, exception);
                }

                try
                {
                    //uint primaryKey = securityManager.GetNextAvailablePrimaryKey("T_ROLES", "IdRole");
                    string strSql = "INSERT INTO T_ROLES OUTPUT INSERTED.idRole VALUES ( @roleName )";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@roleName", roleName);
                        int primaryKey = (int) command.ExecuteScalar();
                        return new Role((uint)primaryKey, roleName);
                    }
                }
                catch ( Exception exception )
                {
                    throw new SecurityManagerException("Can't insert the role " + roleName, exception);
                }
            }


            public void UpdateRole(Role role)
            {
                try
                {
                    string strSql = "UPDATE T_ROLES SET RoleName=@roleName WHERE IdRole=@idRole";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@idRole", (int)role.Identifier);
                        command.Parameters.AddWithValue("@roleName", role.RoleName);
                        command.ExecuteNonQuery();
                    }
                }
                catch (Exception exception)
                {
                    throw new SecurityManagerException("Cannot update role with pk " + role.Identifier, exception);
                }
            }


            public void DeleteRole(Role role)
            {
                try
                {
                    string strSql = "DELETE FROM T_ROLES WHERE IdRole=@idRole";
                    using (SqlCommand command = new SqlCommand(strSql, this.securityManager.connection))
                    {
                        command.Parameters.AddWithValue("@idRole", (int)role.Identifier);
                        command.ExecuteNonQuery();
                    }
                }
                catch ( Exception exception )
                {
                    throw new SecurityManagerException("Cannot delete role "+role.RoleName, exception);
                }
                
            }
        }
    }
}

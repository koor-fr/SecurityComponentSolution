using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KooR.SecurityComponent
{

    /// <summary>
    ///     This base class of exceptions is thrown when a user attempt a bad access into the secure system.  
    /// </summary>
    public class SecurityManagerException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public SecurityManagerException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public SecurityManagerException(string message, System.Exception inner) : base(message, inner) { }
    }

    /// <summary>
    ///     This exception type is thrown when the provided account informations there invalid.  
    /// </summary>
    public class BadCredentialsException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public BadCredentialsException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public BadCredentialsException(string message, System.Exception inner) : base(message, inner) { }
    }

    /// <summary>
    ///     This exception type is thrown when the account is disabled.
    /// </summary>
    public class AccountDisabledException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public AccountDisabledException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public AccountDisabledException(string message, System.Exception inner) : base(message, inner) { }
    }

    /// <summary>
    ///     This type of exceptions is thrown when a role is already registered into the security manager.
    /// </summary>
    public class RoleAlreadyRegisteredException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public RoleAlreadyRegisteredException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public RoleAlreadyRegisteredException(string message, System.Exception inner) : base(message, inner) { }
    }

    /// <summary>
    ///     This type of exceptions is thrown when a unauthorized user attempt to login into the secure system.
    /// </summary>
    public class UnauthorizedException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public UnauthorizedException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public UnauthorizedException(string message, System.Exception inner) : base(message, inner) { }
    }

    /// <summary>
    ///     This type of exceptions is thrown when a user is already registered into the security manager.
    /// </summary>
    public class UserAlreadyRegisteredException : System.Exception
    {
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        public UserAlreadyRegisteredException(string message) : base(message) { }
        /// <summary>
        ///     Class constructor
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="inner">The previous exeception</param>
        public UserAlreadyRegisteredException(string message, System.Exception inner) : base(message, inner) { }
    }

    public interface IUserManager
    {

        /// <summary>
        ///     Check if the pair login/password represents an autorized user for the considered application.
        ///     If the identity is rejected, an exception will thrown. 
        ///     If the identity is accepted, the connection number of the considered user is increased.
        /// </summary>
        /// <param name="userLogin">The login for the considered user.</param>
        /// <param name="userPassword">The password for the considered user.</param>
        /// <returns>The considered user instance.</returns>
        /// <exception cref="AccountDisabledException">Thrown when the provided account informations there invalid.</exception>
        /// <exception cref="BadCredentialsException">Thrown if the identity is rejected.</exception>
        User CheckCredentials( string userLogin, string userPassword );

        /// <summary>
        ///     Retreive the user instance that have the desired identifier.
        /// </summary>
        /// <param name="userId">The user identifier (the primary key into the security database).</param>
        /// <returns> The selected user instance.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the searched user don't exists.</exception>
        User GetUserById(uint userId);

        /// <summary>
        ///     Retreive the user instance by its login.
        /// </summary>
        /// <param name="login">The user login.</param>
        /// <returns>The selected user instance.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the searched user don't exists.</exception>
        User GetUserByLogin( string login );

        /// <summary>
        ///     Retreive all user instances associated to the specified role.
        /// </summary>
        /// <param name="role">The role that contains expected users.</param>
        /// <returns>A list of users member of this role.</returns>
        /// <exception cref="SecurityManagerException">Thrown when the search can't finish.</exception>
        List<User> GetUsersByRole(Role role);

        /// <summary>
        ///     Insert a new user in the security system. The new used has the specified login and the specified password.
        /// </summary>
        /// <param name="login">The login for the considered user.</param>
        /// <param name="password">The password for the considered user. The specified password is automaticly encoded by this method.</param>
        /// <returns>The new user instance.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the new user cannot be inserted in the security system.</exception>
        /// <exception cref="UserAlreadyRegisteredException">Thrown if the specified login is already registered in the security system.</exception>
        User InsertUser(string login, string password);

        /// <summary>
        ///     Update informations, in the security system, for the specified user.
        /// </summary>
        /// <param name="user">The user instance to update.</param>
        /// <exception cref="SecurityManagerException">Thrown if this manager cannot update the user informations.</exception>
        void UpdateUser(User user);

        /// <summary>
        ///     Delete the specified user from the security system.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <exception cref="SecurityManagerException">Thrown if this manager cannot remove the user.</exception>
        void DeleteUser(User user);

		/// <summary>
        ///     Defines the algorithm used for encode password. User password is stored in encoded format.
        /// </summary>
        /// <param name="password">A password (in clear).</param>
        /// <returns>The encoded password.</returns>
        /// <exception cref="SecurityManagerException">Thrown if password encription failed.</exception>
        string EncryptPassword(string password);
    }

    public interface IRoleManager
    {
        /// <summary>
        ///     Select the role with the identifier specified in parameter.
        /// </summary>
        /// <param name="roleIdentifier">The identifier of the role to returns.</param>
        /// <returns>The selected role.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the searched role don't exists.</exception>
        Role SelectRoleById(uint roleIdentifier);

        /// <summary>
        ///     Select the role with the name specified in parameter.
        /// </summary>
        /// <param name="roleName">The name of the role to returns.</param>
        /// <returns>The selected role.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the searched role don't exists.</exception>
        Role SelectRoleByName( string roleName );

        /// <summary>
        ///     Insert a new role into the used security system.
        /// </summary>
        /// <param name="roleName">The name of the new role.</param>
        /// <returns>The new role.</returns>
        /// <exception cref="SecurityManagerException">Thrown if the role cannot be inserted into the security system.</exception>
        /// <exception cref="RoleAlreadyRegisteredException">Thrown if the specified role name already exists in the security system.</exception>
        Role InsertRole( string roleName );

        /// <summary>
        ///     Update the informations for this role (actually, only the role name).
        /// </summary>
        /// <param name="role">The role to update.</param>
        /// <exception cref="SecurityManagerException">Thrown if the role cannot be updated into the security system.</exception>
        void UpdateRole(Role role);

        /// <summary>
        ///     Delete, on the security system, the specified role.
        /// </summary>
        /// <param name="role">The role to delete.</param>
        /// <exception cref="SecurityManagerException">Thrown if the specified role cannot be deleted from the security system.</exception>
        void DeleteRole(Role role);
    }


    public interface ISecurityManager
    {

        /// <summary>
        ///     Open a session to the considered security service.
        /// </summary>
        /// <exception cref="SecurityManagerException">Thrown when connection to the security service cannot be established.</exception>
        void OpenSession();

        /// <summary>
        ///     Close the session with the considered security service.
        /// </summary>
        /// <exception cref="SecurityManagerException">Thrown when connection to the security service cannot be closed.</exception>
        void Close();

        /// <summary>
        ///     Get the role manager associated to this security manager.
        ///     A role manager provided methods to manage roles.
        /// </summary>
        IRoleManager RoleManager
        {
            get;
        }

        /// <summary>
        ///     Get the user manager associated to this security manager.
        ///     A user manager provided methods to manage users.
        /// </summary>
        IUserManager UserManager
        {
            get;
        }

    }
}

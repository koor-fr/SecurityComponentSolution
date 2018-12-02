using System;
using System.Collections.Generic;


namespace KooR.SecurityComponent
{

    /// <summary>
    ///     This class represents the concept of user for a considered software.
    ///     A user has a number of attributes and a set of roles assigned to it.
    ///     Note: you cannot directly create a User. Instead of, use an UserManager instance.
    /// </summary>
    /// <see cref="KooR.SecurityComponent.Role" />
    /// <see cref="KooR.SecurityComponent.IRoleManager" />
    /// <see cref="KooR.SecurityComponent.ISecurityManager" />
    /// <see cref="KooR.SecurityComponent.IUserManager" />
    public class User
    {

        private ISecurityManager securityManager;

        private uint identifier;
        private string login;
        private string password;
        private uint connectionNumber = 0;
        private DateTime lastConnection = DateTime.Now;
        private uint consecutiveErrors = 0;
        private bool disabled = false;

        private readonly HashSet<Role> roles = new HashSet<Role>();

        private string firstName = "";
        private string lastName = "";
        private string email = "";

        /// <summary>
        ///     Produce an instance of User
        /// </summary>
        /// <param name="securityManager">The security manager that produce this user.</param>
        /// <param name="identifier">The unique identifier of this user.</param>
        /// <param name="login">The login of this user.</param>
        /// <param name="encryptedPassword">The password of this user. This password must be already encrypted.</param>
        /// <exception cref="KooR.SecurityComponent.SecurityManagerException">Thrown when you pass bad value to this constructor</exception>
        public User(ISecurityManager securityManager, uint identifier, string login, string encryptedPassword)
        {
            this.securityManager = securityManager ?? throw new SecurityManagerException("securityManager cannot be null");
            this.Identifier = identifier;
            this.Login = login;
            this.password = encryptedPassword ?? throw new SecurityManagerException("password cannot be null"); ;
        }

        /// <summary>
        ///     Class destructor
        /// </summary>
        ~User()
        {
        }

        /// <summary>
        ///     Get or set the user identifier. Normaly, this identified is used as the primary key in the security storage engine.
        ///     It must be unique within the database. 
        /// </summary>
        public uint Identifier
        {
            get { return this.identifier; }
            set { this.identifier = value; }
        }

        /// <summary>
        ///     Get or set the user login.
        /// </summary>
        /// <exception cref="SecurityManagerException">Throw if the login is null</exception>
        public string Login
        {
            get { return this.login; }
            set { this.login = value ?? throw new SecurityManagerException("login cannot be null"); }
        }

        /// <summary>
        ///     Set the password for this user?
        /// </summary>
        /// <exception cref="SecurityManagerException">Throw if the password name is null</exception>
        public string Password
        {
            set
            {
                if (value == null) throw new SecurityManagerException("password cannot be null");
                this.password = this.securityManager.UserManager.EncryptPassword(value);
            }
        }

        /// <summary>
        ///     Check if the encrypted string (for the specified password) is the same that the encrypted password store in the used security system.
        /// </summary>
        /// <param name="password">The clear password to compare</param>
        /// <returns>true if encrypted version of the password is the same that the user encrypted password. false otherwise.</returns>
        /// <exception cref="SecurityManagerException">Thrown if passwords cannot be compared.</exception>
        public bool isSamePassword(string password)
        {
            return this.securityManager.UserManager.EncryptPassword(password) == this.password;
        }

        /// <summary>
        ///     Get or set the connection number for this user. The connection number is increased as each connection time.
        /// </summary>
        public uint ConnectionNumber
        {
            get { return this.connectionNumber; }
            set { this.connectionNumber = value; }
        }

        /// <summary>
        ///     Get or set the last connection date.
        /// </summary>
        public DateTime LastConnection
        {
            get { return this.lastConnection; }
            set { this.lastConnection = value; }
        }

        /// <summary>
        ///     Get or set the disabled status for this account.
        /// </summary>
        public bool Disabled
        {
            get { return this.disabled; }
            set { this.disabled = value; }
        }

        /// <summary>
        ///     Get or set the consecutive error count. After three consecutive error, account is disabled.
        /// </summary>
        public uint ConsecutiveErrors
        {
            get { return this.consecutiveErrors; }
            set { this.consecutiveErrors = value; }
        }

        /// <summary>
        ///     Get or set the first name for this user.
        /// </summary>
        public string FirstName
        {
            get { return this.firstName; }
            set { this.firstName = value ?? ""; }
        }

        /// <summary>
        ///     Get or set the last name for this user.
        /// </summary>
        public string LastName
        {
            get { return this.lastName; }
            set { this.lastName = value ?? ""; }
        }

        /// <summary>
        ///     Get the full name of this user.
        /// </summary>
        public string FullName
        {
            get { return this.firstName + " " + this.lastName; }
        }

        /// <summary>
        ///     Get or set the last name for this user.
        /// </summary>
        public string Email
        {
            get { return this.email; }
            set { this.email = value ?? ""; }
        }

        /// <summary>
        ///     Checks is this user is associated to the specified role.
        /// </summary>
        /// <param name="role">The expected role</param>
        /// <returns>true is this user has the specified role, false otherwise.</returns>
        public bool IsMemberOfRole( Role role ) {
            foreach( Role aRole in this.roles )
            {
                if (aRole == role) return true;
            }
            return false;
        }

        /// <summary>
        ///     Get the set of all roles associated to this user.
        /// </summary>
        public HashSet<Role> Roles
        {
            get { return this.roles; }
        }

        /// <summary>
        ///     Adds another role to this user.
        /// </summary>
        /// <param name="role">The new role to affect for this user.</param>
        public void AddRole(Role role)
        {
            this.roles.Add(role);
        }

        /// <summary>
        ///     Removes a role to this user.
        /// </summary>
        /// <param name="role">The role to remove for this user.</param>
        public void RemoveRole(Role role)
        {
            this.Roles.Remove(role);
        }


        /// <summary>
        ///     Compare two user instances.
        /// </summary>
        /// <param name="user1">The first user object to compare.</param>
        /// <param name="user2">The second user object to compare.</param>
        /// <returns>Return true if the two objects are equals, false otherwise</returns>
        public static bool operator==( User user1, User user2 )
        {
            return user1.identifier == user2.identifier;
        }

        /// <summary>
        ///     Check difference between two user instances.
        /// </summary>
        /// <param name="user1">The first user object to compare.</param>
        /// <param name="user2">The second user object to compare.</param>
        /// <returns>Return false if the two objects are equals, true otherwise</returns>
        public static bool operator !=(User user1, User user2)
        {
            return user1.identifier != user2.identifier;
        }

        public override bool Equals(Object other)
        {
            if (! (other is User)) return false;
            return this.identifier == ((User)other).identifier;
        }

        public override int GetHashCode()
        {
            return 1442482158 + identifier.GetHashCode();
        }
    }
}

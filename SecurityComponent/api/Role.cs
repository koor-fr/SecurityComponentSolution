using System;

namespace KooR.SecurityComponent
{

    /// <summary>
    ///     This class represents the concept of role. A role is associated with one or more users.
    /// </summary>
    public class Role
    {

        private uint identifier;
        private string roleName;

        /// <summary>
        ///     Create a new role instance.
        /// </summary>
        /// <param name="identifier">The role identifier.</param>
        /// <param name="roleName">The name of the new role.</param>
        public Role(uint identifier = 0, string  roleName = "unknown" )
        {
            this.Identifier = identifier;
            this.RoleName = roleName;
        }

        /// <summary>
        ///     Class destructor
        /// </summary>
        ~Role() { }

        /// <summary>
        ///     Get or set the role identifier. Normaly, this identified is used as the primary key in the security storage engine.
        ///     It must be unique within the database. 
        /// </summary>
        public uint Identifier
        {
            get { return this.identifier; }
            set { this.identifier = value; }
        }

        /// <summary>
        ///     Get or set the role name.
        /// </summary>
        /// <exception cref="SecurityManagerException">Throw if the role name is null</exception>
        public string RoleName
        {
            get { return this.roleName; }
            set { this.roleName = value ?? throw new SecurityManagerException("RoleName cannot be null"); }
        }

        /// <summary>
        ///     Compare two role instances.
        /// </summary>
        /// <param name="user1">The first role object to compare.</param>
        /// <param name="user2">The second role object to compare.</param>
        /// <returns>Return true if the two objects are equals, false otherwise</returns>
        public static bool operator ==(Role role1, Role role2)
        {
            return role1.identifier == role2.identifier;
        }

        /// <summary>
        ///     Check difference between two user instances.
        /// </summary>
        /// <param name="user1">The first role object to compare.</param>
        /// <param name="user2">The second role object to compare.</param>
        /// <returns>Return false if the two objects are equals, true otherwise</returns>
        public static bool operator !=(Role role1, Role role2)
        {
            return role1.identifier != role2.identifier;
        }

        public override bool Equals(Object other)
        {
            if (!(other is Role)) return false;
            return this.identifier == ((Role)other).identifier;
        }

        public override int GetHashCode()
        {
            return 1442482158 + identifier.GetHashCode();
        }
    }
}

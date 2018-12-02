using KooR.SecurityComponent;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AnotherComponentTest.ManualMock
{
    public class SecurityManagerMock : ISecurityManager
    {
        public IRoleManager RoleManager => new RoleManagerMock(this);

        public IUserManager UserManager
        {
            get { return new UserManagerMock(this); }
        }

        public void Close() {}

        public void OpenSession() {}


        private class UserManagerMock : IUserManager
        {
            private User user;

            public UserManagerMock(ISecurityManager securityManager)
            {
                user = new User(securityManager, 1, "root", "admin");
            }

            public User CheckCredentials(string userLogin, string userPassword)
            {
                return user;
            }

            public void DeleteUser(User user) { }

            public string EncryptPassword(string password)
            {
                return password;
            }

            public User GetUserById(uint userId) { return user; }

            public User GetUserByLogin(string login) { return user; }

            public List<User> GetUsersByRole(Role role) { return null; }

            public User InsertUser(string login, string password) { return user; }

            public void UpdateUser(User user) { }
        }

        private class RoleManagerMock : IRoleManager
        {
            private Role role;

            public RoleManagerMock(ISecurityManager securityManager)
            {
                role = new Role(1, "admin");
            }

            public void DeleteRole(Role role) { }

            public Role InsertRole(string roleName) { return role; }

            public Role SelectRoleById(uint roleIdentifier) { return role; }

            public Role SelectRoleByName(string roleName) { return role; }

            public void UpdateRole(Role role) { }
        }
    }
}

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;

namespace LDAP_provider
{
    public class LDAP_Provider
    {
        private const string EveryOne = "everyone";

        private const FileSystemRights AuditRights =
             FileSystemRights.ReadData
            | FileSystemRights.ExecuteFile
            | FileSystemRights.WriteData
            | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.CreateDirectories
            | FileSystemRights.CreateFiles
            | FileSystemRights.TakeOwnership;

        //for new user, set userAccountControl property:
        //int userControlFlags = UF_PASSWD_NOTREQD + UF_NORMAL_ACCOUNT + UF_DONT_EXPIRE_PASSWD;
        //deUser.InvokeSet("userAccountControl", userControlFlags);
        //see all: https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
        const int UF_ACCOUNTDISABLE = 0x0002;
        const int UF_PASSWD_NOTREQD = 0x0020;
        const int UF_PASSWD_CANT_CHANGE = 0x0040;
        const int UF_NORMAL_ACCOUNT = 0x0200; // = 512
        const int UF_DONT_EXPIRE_PASSWD = 0x10000;
        const int UF_SMARTCARD_REQUIRED = 0x40000;
        const int UF_PASSWORD_EXPIRED = 0x800000;

        public static bool ValidateCredentials(string sUserName, string sPassword, string domain)
        {
            return GetPrincipalContext(domain).ValidateCredentials(sUserName, sPassword);
        }

        public static bool IsUserExpired(string sUserName, string domain)
        {
            return GetUser(sUserName, domain).AccountExpirationDate != null ? false : true;
        }

        public static bool IsUserExisiting(string sUserName, string domain)
        {
            return GetUser(sUserName, domain) == null ? false : true;
        }

        public static string GetUserDomain(string sUserName, IEnumerable<string> domains)
        {
            foreach (var domain in domains)
            {
                if (GetUser(sUserName, domain) != null)
                    return domain;
            }

            return null;
        }

        public static bool IsAccountLocked(string sUserName, string domain)
        {
            return GetUser(sUserName, domain).IsAccountLockedOut();
        }

        public static UserPrincipal GetUser(string sUserName, string domain)
        {
            if (string.IsNullOrWhiteSpace(sUserName)) return null;

            PrincipalContext oPrincipalContext = GetPrincipalContext(domain);

            return UserPrincipal.FindByIdentity(oPrincipalContext, IdentityType.SamAccountName, sUserName);
        }

        public static UserPrincipal GetUser(string sUserName, string domain, string OU)
        {
            if (string.IsNullOrWhiteSpace(sUserName)) return null;

            PrincipalContext oPrincipalContext = GetPrincipalContext(OU, domain);

            return UserPrincipal.FindByIdentity(oPrincipalContext, IdentityType.SamAccountName, sUserName);
        }

        public static GroupPrincipal GetGroup(string sGroupName, string domain)
        {
            if (string.IsNullOrWhiteSpace(sGroupName)) return null;

            PrincipalContext oPrincipalContext = GetPrincipalContext(domain);

            return GroupPrincipal.FindByIdentity(oPrincipalContext, sGroupName);
        }

        public static SecurityIdentifier GetGroupSID(string sGroupName, string domain)
        {
            if (string.IsNullOrWhiteSpace(sGroupName)) 
                throw new Exception("Group name is empty");

            var group = GetGroup(sGroupName, domain);
            var sid = group.Sid.ToString();

            return new SecurityIdentifier(sid);
        }

        public static SecurityIdentifier GetUserSID(string sUserName, string domain, string OU = null)
        {
            if (string.IsNullOrWhiteSpace(sUserName)) 
                throw new Exception("User name is empty");

            UserPrincipal user = string.IsNullOrWhiteSpace(OU) ? GetUser(sUserName, domain) : GetUser(sUserName, domain, OU);
            var sid = user.Sid.ToString();

            return new SecurityIdentifier(sid);
        }

        public static void CreateNewGroup(string sOU, string sGroupName, GroupScope oGroupScope, string domain)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext(sOU, domain);
            GroupPrincipal oGroupPrincipaldd = GroupPrincipal.FindByIdentity(oPrincipalContext, sGroupName);

            if (oGroupPrincipaldd == null)
            {
                GroupPrincipal oGroupPrincipal = new GroupPrincipal(oPrincipalContext, sGroupName)
                {
                    GroupScope = oGroupScope
                };
                oGroupPrincipal.Save();
            }
        }

        public static void RemoveGroup(string ou, string groupName, string domain, bool removeMembers = false)
        {
            using (PrincipalContext pc = GetPrincipalContext(ou, domain))
            {
                GroupPrincipal oGroupPrincipal = GroupPrincipal.FindByIdentity(pc, groupName);

                if (oGroupPrincipal != null)
                {
                    if (removeMembers)
                    {
                        oGroupPrincipal.Members.Clear();
                        oGroupPrincipal.Save();
                    }
                    oGroupPrincipal.Delete();
                }
            }
        }

        public static void RemoveAllMemebersFromGroup(string ou, string groupName, string domain)
        {
            using (PrincipalContext pc = GetPrincipalContext(ou, domain))
            {
                GroupPrincipal oGroupPrincipal = GroupPrincipal.FindByIdentity(pc, groupName);

                if (oGroupPrincipal != null)
                {
                    oGroupPrincipal.Members.Clear();
                    oGroupPrincipal.Save();
                }
            }
        }

        public static bool AddUserToGroup(string sUserName, string sGroupName, string groupDomain, string userDomain = null)
        {
            if (string.IsNullOrWhiteSpace(userDomain)) userDomain = groupDomain;

            using (PrincipalContext groupContext = new PrincipalContext(ContextType.Domain, groupDomain))
            using (PrincipalContext userContext = new PrincipalContext(ContextType.Domain, userDomain))
            {
                GroupPrincipal oGroupPrincipal = GroupPrincipal.FindByIdentity(groupContext, sGroupName);
                UserPrincipal oUserPrincipal = GetUser(sUserName, userDomain);

                if (oGroupPrincipal != null && oUserPrincipal != null)
                {
                    if (!IsUserGroupMember(sUserName, sGroupName, groupDomain, userDomain))
                    {
                        oGroupPrincipal.Members.Add(oUserPrincipal);
                        oGroupPrincipal.Save();
                    }
                }
            }

            return true;
        }

        public static bool AddGroupToGroup(string sMemberGroupName, string sGroupName, string groupDomain)
        {
            GroupPrincipal oGroupPrincipal = GetGroup(sGroupName, groupDomain);

            if (oGroupPrincipal == null) 
                throw new Exception($"Can't find group {sGroupName} in domain {groupDomain}");

            GroupPrincipal oMemberGroupPrincipal = GetGroup(sMemberGroupName, groupDomain);

            if (oMemberGroupPrincipal == null) 
                throw new Exception($"Can't find group {sMemberGroupName} in domain {groupDomain}");

            if (!IsGroupMemberOfGroup(sMemberGroupName, sGroupName, groupDomain))
            {
                oGroupPrincipal.Members.Add(oMemberGroupPrincipal);
                oGroupPrincipal.Save();
            }

            return true;
        }

        public static bool RemoveGroupFromGroup(string sMemberGroupName, string sGroupName, string groupDomain)
        {
            GroupPrincipal oGroupPrincipal = GetGroup(sGroupName, groupDomain);

            if (oGroupPrincipal == null) 
                throw new Exception($"Can't find group {sGroupName} in domain {groupDomain}");

            GroupPrincipal oMemberGroupPrincipal = GetGroup(sMemberGroupName, groupDomain);

            if (oMemberGroupPrincipal == null) 
                throw new Exception($"Can't find group {sMemberGroupName} in domain {groupDomain}");

            if (IsGroupMemberOfGroup(sMemberGroupName, sGroupName, groupDomain))
            {
                oGroupPrincipal.Members.Remove(oMemberGroupPrincipal);
                oGroupPrincipal.Save();
            }

            return true;
        }

        public static bool RemoveUserFromGroup(string sUserName, string sGroupName, string groupDomain, string userDomain = null)
        {
            if (string.IsNullOrWhiteSpace(userDomain)) userDomain = groupDomain;

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, userDomain))
            using (GroupPrincipal oGroupPrincipal = GetGroup(sGroupName, groupDomain))
            {
                if (oUserPrincipal != null && oGroupPrincipal != null)
                {
                    if (IsUserGroupMember(sUserName, sGroupName, groupDomain, userDomain))
                    {
                        oGroupPrincipal.Members.Remove(oUserPrincipal);
                        oGroupPrincipal.Save();
                    }
                }
            }

            return true;
        }

        public static bool IsGroupMemberOfGroup(string sMemberGroupName, string sGroupName, string groupDomain)
        {
            GroupPrincipal oGroupPrincipal = GetGroup(sGroupName, groupDomain);

            if (oGroupPrincipal == null) 
                throw new Exception($"Can't find group {sGroupName} in domain {groupDomain}");

            GroupPrincipal oMemberGroupPrincipal = GetGroup(sMemberGroupName, groupDomain);

            if (oMemberGroupPrincipal == null) 
                throw new Exception($"Can't find group {sMemberGroupName} in domain {groupDomain}");

            return oMemberGroupPrincipal.IsMemberOf(oGroupPrincipal); ;
        }

        public static bool IsUserGroupMember(string sUserName, string sGroupName, string groupDomain, string userDomain = null)
        {
            bool bResult = false;

            if (string.IsNullOrWhiteSpace(userDomain)) userDomain = groupDomain;

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, userDomain))
            using (GroupPrincipal oGroupPrincipal = GetGroup(sGroupName, groupDomain))
            {
                if (oUserPrincipal != null && oGroupPrincipal != null)
                {
                    bResult = oUserPrincipal.IsMemberOf(oGroupPrincipal);
                }
            }

            return bResult;
        }

        public static List<string> GetUserGroups(string sUserName, string domain)
        {
            List<string> myItems = new List<string>();

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, domain))
            using (PrincipalSearchResult<Principal> oPrincipalSearchResult = oUserPrincipal.GetGroups())
            {
                foreach (Principal oResult in oPrincipalSearchResult)
                {
                    myItems.Add(oResult.Name);
                }
            }

            return myItems;
        }

        public static List<string> RemoveUserFromAllGroups(string sUserName, string userDomain, IEnumerable<string> baseGroups, string groupsDomain = null)
        {
            if (string.IsNullOrWhiteSpace(groupsDomain)) groupsDomain = userDomain;

            var removedGroups = new List<string>();
            var userGroups = GetUserGroups(sUserName, userDomain);

            if (userGroups.Any())
            {
                foreach (var groupToRemove in userGroups.Except(baseGroups))
                {
                    if (RemoveUserFromGroup(sUserName, groupToRemove, groupsDomain, userDomain))
                    {
                        removedGroups.Add(groupToRemove);
                    }
                }
            }

            return removedGroups;
        }

        public static List<string> GetUserAuthorizationGroups(string sUserName, string domain)
        {
            List<string> myItems = new List<string>();
            UserPrincipal oUserPrincipal = GetUser(sUserName, domain);

            using (PrincipalSearchResult<Principal> oPrincipalSearchResult = oUserPrincipal.GetAuthorizationGroups())
            {
                foreach (Principal oResult in oPrincipalSearchResult)
                {
                    myItems.Add(oResult.Name);
                }
            }

            return myItems;
        }

        public static void CreateDirectory(string directoryName)
        {
            if (!Directory.Exists(directoryName))
                Directory.CreateDirectory(directoryName);
        }

        public static void RemoveDirectory(string directoryPath, bool withSubdirectories = false)
        {
            if (Directory.Exists(directoryPath))
            {
                if (withSubdirectories) RemoveDirectoryAndFiles(directoryPath);
                else Directory.Delete(directoryPath);
            }
        }

        private static void RemoveDirectoryAndFiles(string path)
        {
            var subDirectories = Directory.GetDirectories(path);

            foreach (var directoryPath in subDirectories)
                RemoveDirectoryAndFiles(directoryPath);

            var files = Directory.GetFiles(path);

            foreach (var filePath in files)
            {
                try
                {
                    File.Delete(filePath);
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("because it is being used by another process."))
                        throw new Exception($"File {filePath} is being used by another process");

                    throw ex;
                }
            }

            Directory.Delete(path);
        }

        public static List<string> GetSimilarDirectories(string path, string directoryName)
        {
            var similarDirectories = new List<string>();

            if (!Directory.Exists(path)) 
                throw new Exception($"Path {path} doesn't exist");

            foreach (var subDirectory in Directory.GetDirectories(path).Select(s => Path.GetFileName(s)))
            {
                if (subDirectory == directoryName
                    || (subDirectory.Contains(directoryName)
                        && Regex.Match(subDirectory.Remove(subDirectory.IndexOf(directoryName), directoryName.Length),
                        @"^[0-9]+_$").Success))
                {
                    similarDirectories.Add(subDirectory);
                }
            }

            return similarDirectories;
        }

        public static List<string> GetUsersDirectoriesFromPath(string path, string accountName)
        {
            var result = new List<string>();

            if (!path.Contains(accountName)) return result;

            var startIndex = path.IndexOf(accountName);
            var directories = path.Substring(startIndex).Split('\\').ToList();

            foreach (var d in directories.Where(w => !string.IsNullOrEmpty(w)))
                result.Add(path.Substring(0, path.IndexOf($"\\{d}")) + $"\\{d}");

            return result;
        }

        public static void RenameDirectory(string oldDirectoryPath, string newDirectoryPath)
        {
            if (!Directory.Exists(oldDirectoryPath))
            {
                throw new Exception("Directory " + oldDirectoryPath + " doesn't exist");
            }

            if (Directory.Exists(newDirectoryPath))
            {
                throw new Exception("Directory " + newDirectoryPath + " already exists");
            }

            Directory.Move(oldDirectoryPath, newDirectoryPath);
        }

        public static void AddDirectoryPermissionsForGroup(string directoryName, string groupName, string groupDomain,
            FileSystemRights groupRights, InheritanceFlags inheritanceFlags, AccessControlType accessType,
            bool enableInheritanceProtection = true)
        {
            var groupSID = GetGroupSID(groupName, groupDomain);

            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);

            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();

            dirSecurity.AddAccessRule(new FileSystemAccessRule(groupSID,
                groupRights, inheritanceFlags, PropagationFlags.None, accessType));

            if (enableInheritanceProtection)
                dirSecurity.SetAccessRuleProtection(true, false);
            else
                dirSecurity.SetAccessRuleProtection(false, true);

            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void AddDirectoryPermissionsForUser(string directoryName, string userName, string userDomain,
            FileSystemRights userRights, InheritanceFlags inheritanceFlags, AccessControlType accessType,
            bool enableInheritanceProtection = true)
        {
            var userSID = GetUserSID(userName, userDomain);
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.AddAccessRule(new FileSystemAccessRule(userSID,
                userRights, inheritanceFlags, PropagationFlags.None, accessType));

            if (enableInheritanceProtection)
                dirSecurity.SetAccessRuleProtection(true, false);
            else
                dirSecurity.SetAccessRuleProtection(false, true);

            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void SetAccessRuleProtectionOff(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.SetAccessRuleProtection(true, false);
        }

        public static void SetAccessRuleProtectionOn(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.SetAccessRuleProtection(true, true);
        }

        public static bool AreAccessRulesProtected(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();

            return dirSecurity.AreAccessRulesProtected;
        }

        public static void AddAuditChangeRight(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.AddAuditRule(new FileSystemAuditRule(EveryOne, AuditRights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AuditFlags.Success | AuditFlags.Failure));
            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void RemoveAuditChangeRight(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.AddAuditRule(new FileSystemAuditRule(EveryOne, AuditRights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AuditFlags.Success));
            dirSecurity.RemoveAuditRule(new FileSystemAuditRule(EveryOne, AuditRights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AuditFlags.Success));
            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void AddAuditChangeAcl(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.AddAuditRule(new FileSystemAuditRule(EveryOne, FileSystemRights.ChangePermissions, AuditFlags.Success | AuditFlags.Failure));
            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void RemoveAuditChangeAcl(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            dirSecurity.RemoveAuditRule(new FileSystemAuditRule(EveryOne, FileSystemRights.ChangePermissions, AuditFlags.Success | AuditFlags.Failure));
            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static void RemoveGroupAndPermissions(string directoryName, string groupName, FileSystemRights groupRights, AccessControlType accessType)
        {
            if (Directory.Exists(directoryName))
            {
                DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
                DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
                dirSecurity.RemoveAccessRule(new FileSystemAccessRule(groupName, groupRights, accessType));
                directoryInfo.SetAccessControl(dirSecurity);
            }
        }

        public static void RemoveGroupAndPermissionsAll(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();
            AuthorizationRuleCollection rules = dirSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

            foreach (FileSystemAccessRule rule in rules)
                dirSecurity.RemoveAccessRule(rule);

            directoryInfo.SetAccessControl(dirSecurity);
        }

        public static AuthorizationRuleCollection GetAccessControl(string directoryName)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            DirectorySecurity dirSecurity = directoryInfo.GetAccessControl();

            return directoryInfo.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
        }

        public static void SetAccessControl(string directoryName, AuthorizationRuleCollection rules)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(directoryName);
            var dirSecurit = directoryInfo.GetAccessControl();

            foreach (FileSystemAccessRule rule in rules)
            {
                dirSecurit.AddAccessRule(rule);
            }

            directoryInfo.SetAccessControl(dirSecurit);
        }

        public static string CreateUser(UserData userData)
        {
            if (string.IsNullOrWhiteSpace(userData.accountName))
                throw new Exception($"User account name is empty");

            if (IsUserExists(userData.accountName, userData.userDomainName))
            {
                return $"User {userData.accountName} already exists in domain {userData.userDomainName}";
            }

            if (string.IsNullOrWhiteSpace(userData.password))
                throw new Exception($"Password for {userData.accountName} is empty");

            using (PrincipalContext principalContext = GetPrincipalContext(userData.userOU, userData.userDomainName))
            {
                using (var user = new UserPrincipal(principalContext))
                {
                    user.SamAccountName = userData.accountName;
                    user.SetPassword(userData.password);
                    user.Enabled = userData.enabled;
                    user.DisplayName = userData.displayName;
                    user.EmailAddress = userData.email;
                    user.GivenName = userData.firstName;
                    user.Surname = userData.lastName;
                    user.HomeDirectory = userData.homeDirectory;
                    user.HomeDrive = userData.homeDrive;

                    if (!(string.IsNullOrEmpty(userData.userDomainName) || string.IsNullOrEmpty(userData.accountName)))
                    {
                        user.UserPrincipalName = $"{userData.accountName}@{userData.userDomainName}";
                    }
                    else
                    {
                        throw new Exception($"Account name or domain is empty for User {userData.accountName}");
                    }

                    if (userData.passwordExpired)
                    {
                        user.ExpirePasswordNow();
                    }

                    user.Save();

                    if (!string.IsNullOrEmpty(userData.profilePath))
                        SetAdditionalProperty(userData.accountName, userData.userDomainName, "ProfilePath", userData.profilePath);

                    int userControlFlags = UF_NORMAL_ACCOUNT; //prevent PASSWD_NOTREQA flag from setting to true (value by default - 544)
                    SetAdditionalProperty(userData.accountName, userData.userDomainName, "userAccountControl", userControlFlags);
                }
            }

            if (!IsUserExists(userData.accountName, userData.userDomainName))
                throw new Exception($"Unsuccessful attempt to create User {userData.accountName}");

            return string.Empty;
        }

        public static string RemoveUser(string userName, string domain)
        {
            if (!IsUserExists(userName, domain))
            {
                return $"User {userName} doesn't exist in domain {domain}";
            }

            using (UserPrincipal oUserPrincipal = GetUser(userName, domain))
            {
                oUserPrincipal.Delete();

                if (IsUserExists(userName, domain))
                    throw new Exception($"Unsuccessful attempt to remove User {userName}");
            }

            return string.Empty;
        }

        public static string UpdateUser(UserData userData)
        {
            if (string.IsNullOrWhiteSpace(userData.accountName))
                throw new Exception($"User account name is empty");

            if (!IsUserExists(userData.accountName, userData.userDomainName))
            {
                return $"User {userData.accountName} doesn't exist in domain {userData.userDomainName}";
            }

            using (UserPrincipal user = GetUser(userData.accountName, userData.userDomainName))
            {
                user.GivenName = userData.firstName;
                user.Surname = userData.lastName;
                user.Save();
            }

            return string.Empty;
        }

        public static bool IsUserExists(string sUserName, string domain)
        {
            return GetUser(sUserName, domain) == null ? false : true;
        }

        public static bool IsUserEnabled(string sUserName, string domain)
        {
            if (!IsUserExists(sUserName, domain)) 
                throw new Exception($"User {sUserName} wasn't found in domain {domain}");

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, domain))
            {
                return oUserPrincipal.Enabled ?? false;
            }
        }

        public static string EnableUser(string sUserName, string domain)
        {
            if (!IsUserExists(sUserName, domain)) 
                throw new Exception($"User {sUserName} wasn't found in domain {domain}");

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, domain))
            {
                if (!(oUserPrincipal.Enabled ?? false))
                {
                    oUserPrincipal.Enabled = true;
                    oUserPrincipal.Save();

                    if (!(oUserPrincipal.Enabled ?? false))
                        throw new Exception($"Unsuccessful attempt to enable User {sUserName}");
                }
                else
                {
                    return $"User {sUserName} already enabled";
                }
            }

            return string.Empty;
        }

        public static string DisableUser(string sUserName, string domain)
        {
            if (!IsUserExists(sUserName, domain)) 
                throw new Exception($"User {sUserName} wasn't found in domain {domain}");

            using (UserPrincipal oUserPrincipal = GetUser(sUserName, domain))
            {
                if (oUserPrincipal.Enabled ?? true)
                {
                    oUserPrincipal.Enabled = false;
                    oUserPrincipal.Save();

                    if (oUserPrincipal.Enabled ?? true)
                        throw new Exception($"Unsuccessful attempt to disable User {sUserName}");
                }
                else
                {
                    return $"User {sUserName} already disabled";
                }
            }

            return string.Empty;
        }

        #region Help methods

        public static PrincipalContext GetPrincipalContext(string Domain)
        {
            return new PrincipalContext(ContextType.Domain, Domain);
        }

        public static PrincipalContext GetPrincipalContext(string ou, string domain)
        {
            return new PrincipalContext(ContextType.Domain, domain, ou);
        }

        private static void SetAdditionalProperty<T>(string userName, string domainName, string propertyName, T propertyValue)
        {
            using (UserPrincipal user = GetUser(userName, domainName))
            {
                if (user == null) 
                    throw new Exception($"Can't find user '{userName}' in domain '{domainName}'");

                using (DirectoryEntry entry = user.GetUnderlyingObject() as DirectoryEntry)
                {
                    if (entry == null) 
                        throw new Exception($"Unable to set properties of user '{userName}'");

                    entry.InvokeSet(propertyName, propertyValue);
                    entry.CommitChanges();
                }
            }
        }

        private static void SetAdditionalMultivalueProperty<T>(string userName, string domainName, string propertyName, List<T> propertyValues)
        {
            using (UserPrincipal user = GetUser(userName, domainName))
            {
                if (user == null) 
                    throw new Exception($"Can't find user '{userName}' in domain '{domainName}'");

                using (DirectoryEntry entry = user.GetUnderlyingObject() as DirectoryEntry)
                {
                    if (entry == null) 
                        throw new Exception($"Unable to set properties of user '{userName}'");

                    PropertyValueCollection valueCollection = entry.Properties[propertyName];

                    foreach (var propertyValue in propertyValues)
                    {
                        valueCollection.Add(propertyValue);
                    }

                    entry.CommitChanges();
                }
            }
        }

        #endregion
    }

    public struct UserData
    {
        public string displayName;
        public string accountName;
        public string password;
        public bool enabled;
        public string email;
        public string firstName;
        public string lastName;
        public bool passwordExpired;
        public string userOU;
        public string homeDirectory;
        public string profileDirectory;
        public string homeDrive;
        public string profilePath;
        public string userDomainName;
        public string domainBaseAccount;
        public string profileFolders;
        public string adminGroups;
    }
}

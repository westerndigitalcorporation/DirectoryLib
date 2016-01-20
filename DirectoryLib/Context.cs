// The MIT License (MIT)
// Copyright (c) 2015 Western Digital Technologies, Inc. <copyrightagent@wdc.com>
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. 
// SPDX-License-Identifier:     MIT

using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Text.RegularExpressions;
using Wdc.DirectoryLib.Types;

namespace Wdc.DirectoryLib
{
    /// <summary>
    /// Wrapper around Active Directory Services
    /// </summary>
    public class Context
    {
        private string gcHostname;

        /// <summary>
        /// Initialize new instance of this active directory context.
        /// </summary>
        /// <param name="gcHostname">The Global Catelog Hostname a Domain Controller.
        /// If no hostname is provided, the current context is used.
        /// </param>
        public Context(string gcHostname = "")
        {
            if (string.IsNullOrEmpty(gcHostname))
            {
                var context = new DirectoryContext(DirectoryContextType.Forest);
                this.gcHostname = GlobalCatalog.FindOne(context).Name;
            }
            else
            {
                this.gcHostname = gcHostname;
            }
        }

        /// <summary>
        /// Get user by domain (exmpl.wdc.com) and SAM Account Name (last_f)
        /// </summary>
        /// <param name="domain">Domain (exmpl.wdc.com)</param>
        /// <param name="samAccountName">SAM Account Name (last_f)</param>
        public UserAccount GetUser(string domain, string samAccountName)
        {
            if (string.IsNullOrEmpty(domain))
            {
                throw new ArgumentException("Invalid argument: domain is null or empty", "domain");
            }

            if (string.IsNullOrEmpty(samAccountName))
            {
                throw new ArgumentException("Invalid argument: samAccountName is null or empty", "samAccountName");
            }

            string branch = "DC=" + domain.Replace(".", ",DC=");
            string path = GetGCPath(branch);
            string filter = string.Format("(&(objectClass=person)(samAccountName={0}))", samAccountName);

            using (var entry = new DirectoryEntry(path))
            using (var search = new DirectorySearcher(entry, filter))
            {
                SearchResult result = search.FindOne();
                if (result == null)
                {
                    return null;
                }
                else
                {
                    return GetUserFromResult(result);
                }
            }
        }

        /// <summary>
        /// Get user by email address (user@exampl.wdc.com)
        /// </summary>
        /// <param name="email">Email address (user@exmpl.wdc.com)</param>
        public UserAccount GetUserByEmail(string email)
        {
            string path = GetGCPath();
            string filter = string.Format("(&(objectClass=person)(mail={0}))", email);

            using (var entry = new DirectoryEntry(path))
            using (var search = new DirectorySearcher(entry, filter))
            {
                SearchResult result = search.FindOne();
                if (result == null)
                {
                    return null;
                }
                else
                {   
                    return GetUserFromResult(result);
                }

            }
        }
        
        /// <summary>
        /// Get user by UserPrincipalName (last_f@exmpl.wdc.com)
        /// </summary>
        /// <param name="upn">UserPrincipalName (last_f@exmpl.wdc.com)</param>
        public UserAccount GetUserByUpn(string upn)
        {
            string path = GetGCPath();
            string filter = string.Format("(&(objectClass=person)(userPrincipalName={0}))", upn);

            using (var entry = new DirectoryEntry(path))
            using (var search = new DirectorySearcher(entry, filter))
            {
                SearchResult result = search.FindOne();
                if (result == null)
                {
                    return null;
                }
                else
                {
                    return GetUserFromResult(result);
                }
            }
        }

        /// <summary>
        /// Get user by NT Name (exmpl\last_f).
        /// This can be slower than other GetUser() methods due to a call to GetDomainNameByNetBios()
        /// </summary>
        /// <param name="ntName">NT Name (exmpl\last_f)</param>
        public UserAccount GetUserByNtName(string ntName)
        {
            string[] a = ntName.Split('\\');
            if (a.Length != 2)
            {
                throw new ArgumentException("Invalid ntName '" + ntName + "'. Expected one \\ symbol.", "ntName");
            }
            string netbios = a[0];
            string samName = a[1];
            string domain = GetDomainNameByNetBios(netbios);
            if (domain == null)
            {
                throw new ArgumentException("Could not convert NetBios '" + netbios + "' to Domain.", "ntName");
            }
            return GetUser(domain, samName);
        }

        /// <summary>
        /// Perform authentication and return the status for the account.
        /// </summary>
        /// <param name="user">The user account object</param>
        /// <param name="password">The user password in plaintext</param>
        /// <param name="daysToExpiration">The number of days until the password expires</param>
        public AccountStatus Authenticate(UserAccount user, string password, long daysToExpiration = 0)
        {
            if (daysToExpiration == 0)
            {
                // If the caller does not provide expiration, use the domain policy
                daysToExpiration = GetMaxPasswordAgeInDays(user.Domain);
            }

            AccountStatus status = AccountStatus.UserNotFound;

            if (user != null)
            {   
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, gcHostname))
                using (UserPrincipal u = UserPrincipal.FindByIdentity(pc, IdentityType.DistinguishedName, user.DistinguishedName))
                {
                    if (u == null)
                    {
                        status = AccountStatus.UserNotFound;
                    }
                    else if (u.PasswordNotRequired)
                    {
                        status = AccountStatus.Success;
                    }
                    else if (pc.ValidateCredentials(user.SamAccountName, password))
                    {
                        status = AccountStatus.Success;
                    }
                    else if (u.IsAccountLockedOut())
                    {
                        status = AccountStatus.UserLockedOut;
                    }
                    else if (!u.PasswordNeverExpires && u.LastPasswordSet == null)
                    {
                        status = AccountStatus.MustChangePassword;
                    }
                    else if (!u.PasswordNeverExpires && (DateTime.Now - u.LastPasswordSet.Value).TotalDays >= daysToExpiration)
                    {
                        status = AccountStatus.ExpiredPassword;
                    }
                    else
                    {
                        status = AccountStatus.InvalidPassword;
                    }
                }
            }

            return status;
        }

        /// <summary>
        /// Convert DomainName (exmpl.wdc.com) to NetBiosName (exmpl)
        /// </summary>
        /// <param name="domainName">Domain Name (exmpl.wdc.com)</param>
        /// <returns>NetBiosName (exmpl)</returns>
        public string GetNetBiosNameByDomainName(string domainName)
        {
            string distinguishedName = string.Empty;

            if (Regex.Match(domainName, @"(?:(?:dc=\w+),?)+").Success)
            {
                distinguishedName = domainName;
            }
            else if (Regex.Match(domainName, @"(\w+.?)+").Success)
            {
                distinguishedName = Regex.Replace(
                    domainName,
                    @"\w+.?",
                    (Match m) => string.Format("DC={0}", m.Groups[0].Value).Replace('.', ',')
                );
            }
            else
            {
                throw new ArgumentException("Invalid format", "dn");
            }

            using (DirectoryEntry entry = new DirectoryEntry(string.Format("GC://{0}", gcHostname)))
            using (var search = new DirectorySearcher(entry, string.Format("(&(objectClass=domain)(distinguishedName={0}))", distinguishedName)))
            {
                SearchResult result = search.FindOne();

                return result == null ? null : TryGetResult<string>(result, "dc");
            }
        }

        /// <summary>
        /// Convert NetBiosName (exmpl) to DomainName (exmpl.wdc.com)
        /// </summary>
        /// <param name="netBiosName">NetBiosName (exmpl)</param>
        /// <returns>DomainName (exmpl.wdc.com)</returns>
        public string GetDomainNameByNetBios(string netBiosName)
        {
            string domainName = null;

            using (DirectoryEntry entry = new DirectoryEntry(GetGCPath()))
            using (DirectorySearcher search = new DirectorySearcher(entry, string.Format("(&(objectClass=domain)(dc={0}))", netBiosName)))
            {
                SearchResult result = search.FindOne();
                if (result != null)
                {
                    string distinguishedName = TryGetResult<string>(result, "distinguishedName");
                    domainName = distinguishedName.Replace(",DC=", ".").Replace("DC=", string.Empty);
                }
            }

            return domainName;
        }

        /// <summary>
        /// Gets the maxPwdAge property on the domain (exmpl.wdc.com).
        /// This is days until the password expires unless the account has PasswordNeverExpires.
        /// </summary>
        /// <param name="domain">Domain Name (exmpl.wdc.com)</param>
        /// <returns>Days until a password expires</returns>
        public long GetMaxPasswordAgeInDays(string domain)
        {
            long days = 0;
            const long NS_IN_A_DAY = -864000000000;

            string branch = "DC=" + domain.Replace(".", ",DC=");
            string path = string.Format("LDAP://{0}/{1}", domain, branch);
            string filter = "(maxPwdAge=*)";

            using (var entry = new DirectoryEntry(path))
            using (var search = new DirectorySearcher(entry, filter, new string[] { "+", "*" }, SearchScope.Base))
            {
                var result = search.FindOne();
                if (result.Properties.Contains("maxPwdAge"))
                {
                    long maxPwdAge = TryGetResult<long>(result, "maxPwdAge");

                    days = maxPwdAge / NS_IN_A_DAY;
                }
            }

            return days;
        }

        /// <summary>
        /// Returns UserAccount object from a given search result
        /// </summary>
        /// <param name="result">SearchResult computed by one of the other GetUser methods</param>
        private UserAccount GetUserFromResult(SearchResult result)
        {
            // Values can be found here:
            // http://msdn.microsoft.com/en-us/library/ms679021(v=vs.85).aspx
            return new UserAccount()
            {
                ObjectGuid = TryGetResult<byte[]>(result, "objectGUID"),
                CommonName = TryGetResult<string>(result, "cn"),
                DisplayName = TryGetResult<string>(result, "displayName"),
                GivenName = TryGetResult<string>(result, "givenName"),
                SurName = TryGetResult<string>(result, "sn"),
                Email = TryGetResult<string>(result, "mail"),
                Department = TryGetResult<string>(result, "department"),
                Title = TryGetResult<string>(result, "title"),
                LocalityName = TryGetResult<string>(result, "l"),
                StateOrProvinceName = TryGetResult<string>(result, "st"),
                CountryName = TryGetResult<string>(result, "c"),
                Phone = TryGetResult<string>(result, "telephoneNumber"),
                Mobile = TryGetResult<string>(result, "mobile"),
                PhysicalDeliveryOfficeName = TryGetResult<string>(result, "physicalDeliveryOfficeName"),
                Description = TryGetResult<string>(result, "description"),
                JpegPhoto = TryGetResult<byte[]>(result, "thumbnailPhoto"),
                DistinguishedName = TryGetResult<string>(result, "distinguishedName"),
                Domain = GetDomainFromUpn(TryGetResult<string>(result, "userPrincipalName")),
                SamAccountName = TryGetResult<string>(result, "samAccountName"),
                UserPrincipalName = TryGetResult<string>(result, "userPrincipalName")
            };
        }

        private T TryGetResult<T>(SearchResult result, string key)
        {
            var valueCollection = result.Properties[key];
            if (valueCollection.Count > 0)
                return (T)valueCollection[0];
            else
                return default(T);
        }

        /// <summary>
        /// Gets domain (exmpl.wdc.com) from upn (last_f@exmpl.wdc.com)
        /// </summary>
        /// <param name="upn">UserPrincipalName (last_f@exmpl.wdc.com)</param>
        private string GetDomainFromUpn(string upn)
        {
            if (upn == null)
            {
                return null;
            }

            string[] a = upn.Split('@');
            if (a.Length != 2)
            {
                return null;
            }
            return a[1];
        }

        private string GetGCPath(string branch = null)
        {
            string path;
            if (!string.IsNullOrEmpty(branch))
            {   
                path = string.Format("GC://{0}/{1}", gcHostname, branch);
            }
            else
            {
                path = string.Format("GC://{0}", gcHostname);
            }

            return path;

        }

        /// <summary>
        /// For debugging purposes only. Prints out the contents of the SearchResult object
        /// </summary>
        /// <param name="result"></param>
        private void PrintOutResult(SearchResult result)
        {
            foreach (var key in result.Properties.PropertyNames)
            {
                var valueCollection = result.Properties[key.ToString()];
                if (valueCollection.Count > 0)
                    Console.WriteLine(key + " : " + valueCollection[0]);
                    
            }
        }
    }
}

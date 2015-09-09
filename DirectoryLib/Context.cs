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
        public Context(string gcHostname="")
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
            string path = string.Format("GC://{0}/{1}", gcHostname, branch);
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
                        Domain = domain,
                        SamAccountName = TryGetResult<string>(result, "samAccountName"),
                        UserPrincipalName = TryGetResult<string>(result, "userPrincipalName")
                    };
                }

            }
        }

        /// <summary>
        /// Get user by UserPrincipalName (last_f@exmpl.wdc.com)
        /// </summary>
        /// <param name="upn">UserPrincipalName (last_f@exmpl.wdc.com)</param>
        public UserAccount GetUserByUpn(string upn)
        {
            string[] a = upn.Split('@');
            if (a.Length != 2)
            {
                throw new ArgumentException("Invalid upn '" + upn + "'. Expected one @ symbol.", "upn");
            }
            string samName = a[0];
            string domain = a[1];
            return GetUser(domain, samName);
        }

        /// <summary>
        /// Get user by NT Name (exmpl\last_f).
        /// This can be slower than other GetUser methods due to a call to GetDomainNameByNetBios
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
        public AccountStatus Authenticate(UserAccount user, string password, int daysToExpiration=89)
        {
            AccountStatus status = AccountStatus.USER_NOT_FOUND;

            if (user != null)
            {
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, user.Domain))
                using (UserPrincipal u = UserPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, user.SamAccountName))
                {
                    if (u == null)
                    {
                        status = AccountStatus.USER_NOT_FOUND;
                    }
                    else if (u.PasswordNotRequired)
                    {
                        status = AccountStatus.PASS_CORRECT;
                    }
                    else if (pc.ValidateCredentials(user.SamAccountName, password))
                    {
                        status = AccountStatus.PASS_CORRECT;
                    }
                    else if (u.IsAccountLockedOut())
                    {
                        status = AccountStatus.USER_LOCKED_OUT;
                    }
                    else if (!u.PasswordNeverExpires && u.LastPasswordSet == null)
                    {
                        status = AccountStatus.PASS_MUST_CHANGE;
                    }
                    else if (!u.PasswordNeverExpires && (DateTime.Now - u.LastPasswordSet).Value.Days > daysToExpiration)
                    {
                        status = AccountStatus.PASS_EXPIRED;
                    }
                    else
                    {
                        status = AccountStatus.PASS_INCORRECT;
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
            Match m1 = Regex.Match(domainName, @"(?:(?:dc=\w+),?)+");
            Match m2 = Regex.Match(domainName, @"(\w+.?)+");

            if (m1.Success)
                distinguishedName = domainName;
            else if (m2.Success)
            {
                distinguishedName = Regex.Replace(domainName, @"\w+.?", delegate(Match match)
                {
                    return string.Format("DC={0}", match.Groups[0].Value).Replace('.', ',');
                });
            }
            else
                throw new ArgumentException("Invalid format", "dn");

            using (var entry = new DirectoryEntry("GC://" + gcHostname))
            {
                using (var search = new DirectorySearcher(entry, string.Format("(&(objectClass=domain)(distinguishedName={0}))", distinguishedName)))
                {
                    SearchResult result = search.FindOne();
                    if (result != null)
                        return TryGetResult<string>(result, "dc");

                    return null;
                }
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
            
            using (DirectoryEntry entry = new DirectoryEntry(string.Format("GC://{0}", gcHostname)))
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

        private T TryGetResult<T>(SearchResult result, string key)
        {
            var valueCollection = result.Properties[key];
            if (valueCollection.Count > 0)
                return (T)valueCollection[0];
            else
                return default(T);
        }

    }
}

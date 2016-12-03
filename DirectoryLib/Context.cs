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
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Text;
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
        private string searchProtocol;

        /// <summary>
        /// Initialize new instance of this active directory context.
        /// </summary>
        /// <param name="gcHostname">The Global Catalog Hostname a Domain Controller.
        /// If no hostname is provided, the current context is used.
        /// <param name="searchType">Whether the searches will be done as GC (default) or LDAP. 
        /// Global Catalog will ensure that the results are searched for in the entire catalog (whether in the host 
        /// or other domains in the forest)
        /// But, if the host controller happens to contains the search entities, LDAP can be faster.</param>
        /// </param>
        public Context(string gcHostname = "", SearchType searchType = SearchType.GlobalCatalog)
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

            searchProtocol = searchType == SearchType.GlobalCatalog ? "GC" : "LDAP";
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

            string branch = ConvertDomainToDistinguishedNameFormat(domain);
            string path = GetDirectoryPath(branch);
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
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under</param>
        public UserAccount GetUserByEmail(string email, string baseDistinguishedName = null)
        {
            string path = GetDirectoryPath(baseDistinguishedName);
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
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under</param>
        public UserAccount GetUserByUpn(string upn, string baseDistinguishedName = null)
        {
            string path = GetDirectoryPath(baseDistinguishedName);
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

        public UserAccount GetUserByDistinguishedName(string distinguishedName)
        {
            string path = GetDirectoryPath();
            string filter = $"(&(objectClass=person)(distinguishedName={distinguishedName}))";

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
        /// Get user by GetUserByGuid
        /// </summary>
        /// <param name="guid">Represents the GUID for the object we are searching for</param>
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under</param>
        public UserAccount GetUserByGuid(Guid guid, string baseDistinguishedName = null)
        {
            var byteArray = guid.ToByteArray();

            // to do the query, we have to format the byte array by prepending each byte with a '\'
            var hex = new StringBuilder(byteArray.Length * 3);
            foreach (byte b in byteArray)
            {
                hex.AppendFormat(@"\{0:X2}", b);
            }

            var hexGuid = hex.ToString();

            string path = GetDirectoryPath(baseDistinguishedName);
            string filter = string.Format("(&(objectClass=person)(objectGUID={0}))", hexGuid);

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
        /// Get user by GUID
        /// </summary>
        /// <param name="guid">Array of 16 bytes</param>
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under</param>
        public UserAccount GetUserByGuid(byte[] guid, string baseDistinguishedName = null)
        {
            if (guid == null || guid.Length != 16)
            {
                throw new ArgumentException("GUID must consist of 16 bytes.");
            }
            var guidObj = new Guid(guid);
            return GetUserByGuid(guidObj, baseDistinguishedName);
        }

        /// <summary>
        /// Get user by GUID
        /// </summary>
        /// <param name="guidString">String (hex) representation of guid (e.g. F47AC10B-58CC-4372-A567-0E02B2C3D479)</param>
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under</param>
        public UserAccount GetUserByGuid(string guidString, string baseDistinguishedName = null)
        {
            return GetUserByGuid(new Guid(guidString), baseDistinguishedName);
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
            AccountStatus status = AccountStatus.UserNotFound;

            if (user != null)
            {
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, user.Domain))
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
                    else
                    {
                        if (daysToExpiration == 0)
                        {
                            // If the caller does not provide expiration, use the domain policy
                            daysToExpiration = GetMaxPasswordAgeInDays(user.Domain);
                        }

                        if (!u.PasswordNeverExpires && (DateTime.Now - u.LastPasswordSet.Value).TotalDays >= daysToExpiration)
                        {
                            status = AccountStatus.ExpiredPassword;
                        }
                        else
                        {
                            status = AccountStatus.InvalidPassword;
                        }
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
            string netBiosName = null;

            if (Regex.Match(domainName, @"(?:(?:dc=\w+),?)+").Success)
            {
                domainName = ConvertDistinguishedNameToDomainFormat(domainName);
            }
            else if (!Regex.Match(domainName, @"(\w+.?)+").Success)
            {
                throw new ArgumentException("Invalid format", "dn");
            }

            using (DirectoryEntry rootDSE = new DirectoryEntry(GetDirectoryPath("RootDSE")))
            {
                string configurationNamingContext = rootDSE.Properties["configurationNamingContext"][0].ToString();

                using (DirectoryEntry searchRoot = new DirectoryEntry("LDAP://cn=Partitions," + configurationNamingContext))
                {
                    using (DirectorySearcher search = new DirectorySearcher(searchRoot, $"(dnsRoot={domainName})"))
                    {
                        SearchResult result = search.FindOne();
                        if (result != null)
                        {
                            netBiosName = TryGetResult<string>(result, "netBiosName");
                        }
                    }
                }
            }

            return netBiosName;
        }

        /// <summary>
        /// Convert NetBiosName (exmpl) to DomainName (exmpl.wdc.com)
        /// </summary>
        /// <param name="netBiosName">NetBiosName (exmpl)</param>
        /// <returns>DomainName (exmpl.wdc.com)</returns>
        public string GetDomainNameByNetBios(string netBiosName)
        {
            string domainName = null;

            using (DirectoryEntry rootDSE = new DirectoryEntry(GetDirectoryPath("RootDSE")))
            {
                string configurationNamingContext = rootDSE.Properties["configurationNamingContext"][0].ToString();

                using (DirectoryEntry searchRoot = new DirectoryEntry("LDAP://cn=Partitions," + configurationNamingContext))
                {
                    using (DirectorySearcher search = new DirectorySearcher(searchRoot, $"(netbiosname={netBiosName})"))
                    {
                        SearchResult result = search.FindOne();
                        if (result != null)
                        {
                            domainName = TryGetResult<string>(result, "dnsRoot");
                        }
                    }
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

            string baseDistinguishedName = ConvertDomainToDistinguishedNameFormat(domain);
            string path = string.Format("LDAP://{0}/{1}", gcHostname, baseDistinguishedName);
            string filter = "(maxPwdAge=*)";

            using (var entry = new DirectoryEntry(path))
            using (var search = new DirectorySearcher(entry, filter, new string[] { "+", "*" }, SearchScope.Base))
            {
                var result = search.FindOne();
                if (result != null && result.Properties.Contains("maxPwdAge"))
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
                Domain = GetDomainFromDistinguishedName(TryGetResult<string>(result, "distinguishedName")),
                SamAccountName = TryGetResult<string>(result, "samAccountName"),
                UserPrincipalName = TryGetResult<string>(result, "userPrincipalName"),
                Manager = TryGetResult<string>(result, "manager"),
                DirectReports = TryGetResultList<string>(result, "directReports"),
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

        private List<T> TryGetResultList<T>(SearchResult result, string key)
        {
            var list = new List<T>();
            var valueCollection = result.Properties[key];
            if (valueCollection.Count > 0)
            {   
                foreach (T val in valueCollection)
                {
                    list.Add(val);
                }
            }
            return list;
        }

        /// <summary>
        /// Extracts the domain component (exmpl.wdc.com) from distinguished name (...DC=exmpl,DC=wdc,DC=com)
        /// </summary>
        /// <param name="distinguishedName">Distinguished Name</param>
        private string GetDomainFromDistinguishedName(string distinguishedName)
        {
            if (distinguishedName == null)
            {
                return null;
            }

            // The assumption is that the domain can be parsed from the distinguished name beginning
            // with the first DC object.
            int domainBegin = distinguishedName.IndexOf("DC=");
            if (domainBegin > -1)
            {
                return ConvertDistinguishedNameToDomainFormat(distinguishedName.Substring(domainBegin));
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Helper function that provides the directory path string to pass onto DirectoryEntry()
        /// constructor.
        /// </summary>
        /// <param name="baseDistinguishedName">Optional distinguished name of domain to search under.</param>
        /// <returns></returns>
        private string GetDirectoryPath(string baseDistinguishedName = null)
        {
            string path;
            
            if (!string.IsNullOrEmpty(baseDistinguishedName))
            {
                path = string.Format("{0}://{1}/{2}", searchProtocol, gcHostname, baseDistinguishedName);
            }
            else
            {
                path = string.Format("{0}://{1}", searchProtocol, gcHostname);
            }

            return path;
        }

        /// <summary>
        /// Convert (example.wdc.com) -> DC=example,DC=wdc,DC=com
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        private string ConvertDomainToDistinguishedNameFormat(string domain)
        {
            return "DC=" + domain.Replace(".", ",DC=");
        }

        /// <summary>
        /// Convert (DC=example,DC=wdc,DC=com) -> example.wdc.com
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private string ConvertDistinguishedNameToDomainFormat(string distinguishedName)
        {
            return distinguishedName.Replace("DC=", string.Empty).Replace(",", ".");
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
                {
                    Console.WriteLine(key + " : " + valueCollection[0]);
                }
            }
        }
    }
}

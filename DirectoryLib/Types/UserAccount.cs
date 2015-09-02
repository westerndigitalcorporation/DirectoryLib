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

using System.Text;

namespace Wdc.DirectoryLib.Types
{
    /// <summary>
    /// The account object for a Person/User in Active Directory.
    /// </summary>
    public class UserAccount
    {
        /// <summary>
        /// The unique identifier for an object.
        /// This 16-byte value is set when the object is created and cannot be changed.
        /// </summary>
        public byte[] ObjectGuid { get; set; }

        /// <summary>
        /// The Guid represented as a Hex String.
        /// Since the Guid is 16 bytes, this string is 32 characters.
        /// </summary>
        public string ObjectGuidAsHex
        {
            get
            {
                var hex = new StringBuilder(this.ObjectGuid.Length * 2);
                foreach (byte b in this.ObjectGuid)
                {
                    hex.AppendFormat("{0:X2}", b);
                }
                return hex.ToString();
            }
        }

        /// <summary>
        /// The common name that is usually the same as DisplayName.
        /// Example: Joe Q. Johnson
        /// </summary>
        public string CommonName { get; set; }

        /// <summary>
        /// The display name for an object. This is usually
        /// the combination of the users first name, middle initial, and last name.
        /// Example: Joe Q. Johnson
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// Contains the given name (first name) of the user.
        /// Example: Joe
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// This attribute contains the family or last name for a user.
        /// Example: Johnson
        /// </summary>
        public string SurName { get; set; }

        /// <summary>
        /// The email address for this contact.
        /// Example: Joe-Q-Johnson@wdc.com
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// The primary telephone number.
        /// Example: 949-672-7000
        /// </summary>
        public string Phone { get; set; }

        /// <summary>
        /// The primary mobile phone number.
        /// </summary>
        public string Mobile { get; set; }

        /// <summary>
        /// Contains the user's job title. This property is commonly used to indicate the formal job title, 
        /// such as Senior Programmer, rather than occupational class, such as programmer.
        /// It is not typically used for suffix titles such as Esq. or DDS.
        /// Example: Sr. Software Engineer
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Contains the name for the department in which the user works.
        /// Example: Software Tools
        /// </summary>
        public string Department { get; set; }

        /// <summary>
        /// Office number or cubicle number.
        /// Example: 1-2079
        /// </summary>
        public string PhysicalDeliveryOfficeName { get; set; }

        /// <summary>
        /// Represents the name of a locality, such as a town or city.
        /// Example: Irvine
        /// </summary>
        public string LocalityName { get; set; }

        /// <summary>
        /// The name of a user's state or province.
        /// Example: CA
        /// </summary>
        public string StateOrProvinceName { get; set; }

        /// <summary>
        /// The country/region in the address of the user.
        /// The country/region is represented as a 2-character code based on ISO-3166.
        /// Example: US
        /// </summary>
        public string CountryName { get; set; }

        /// <summary>
        /// Contains the description to display for an object.
        /// This value is restricted as single-valued for backward compatibility in some cases.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Fully qualified domain name.
        /// Example: exmpl.wdc.com
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// The logon name used to support clients and servers running earlier versions of the operating system, 
        /// such as Windows NT 4.0, Windows 95, Windows 98, and LAN Manager.
        /// This attribute must be 20 characters or less to support earlier clients.
        /// Typically formatted as lastname_f such as johnson_j.
        /// </summary>
        public string SamAccountName { get; set; }

        /// <summary>
        /// This attribute contains the UPN that is an Internet-style login name for a user based on the 
        /// Internet standard RFC 822. The UPN is shorter than the distinguished name and easier to remember. 
        /// By convention, this should map to the user email name, but this is not required.
        /// The value set for this attribute is equal to the length of the user's ID and the domain name.
        /// Typically formatted as lastname_f@domain such as johnson_j@exmpl.wdc.com
        /// </summary>
        public string UserPrincipalName { get; set; }

        /// <summary>
        /// Used to store an image of a person using the JPEG File Interchange Format.
        /// </summary>
        public byte[] JpegPhoto { get; set; }
    }
}

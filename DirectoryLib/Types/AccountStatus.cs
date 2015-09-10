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

namespace Wdc.DirectoryLib.Types
{
    /// <summary>
    /// The result after an authentication attempt.
    /// </summary>
    public enum AccountStatus
    {
        /// <summary>
        /// No user found matching the supplied account credentials. Typically a typo.
        /// </summary>
        UserNotFound = 0,

        /// <summary>
        /// The user supplied the correct credentials and successfully authenticated.
        /// </summary>
        Success,

        /// <summary>
        /// The user supplied the wrong password for the account.
        /// </summary>
        InvalidPassword,

        /// <summary>
        /// The user's password is expired and must be changed. Typically this expires every 90 days.
        /// </summary>
        ExpiredPassword,

        /// <summary>
        /// The "user must change password at next logon" since LastPasswordSet=null. Typically for new accounts.
        /// </summary>
        MustChangePassword,

        /// <summary>
        /// The user account is locked. Typically too many incorrect attempts.
        /// </summary>
        UserLockedOut
    }
}

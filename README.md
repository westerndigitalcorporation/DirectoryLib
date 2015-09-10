# DirectoryLib

A wrapper library for Active Directory (LDAP) authentication in .NET

[![Version](https://img.shields.io/nuget/v/Wdc.DirectoryLib.svg)](https://www.nuget.org/packages/Wdc.DirectoryLib/)
[![Downloads](https://img.shields.io/nuget/dt/Wdc.DirectoryLib.svg)](https://www.nuget.org/packages/Wdc.DirectoryLib/)

## Install

Use the Package Manager Console to install the latest [Wdc.DirectoryLib](https://www.nuget.org/packages/Wdc.DirectoryLib/) package.
```
Install-Package Wdc.DirectoryLib
```

## Usage
```cs
Context context = new Context("domain-controller.example.com");
UserAccount user = context.GetUserByUpn("johnson_j@net.example.com");
AccountStatus status = context.Authenticate(user, "secure-password-123");

switch (status)
{
    case AccountStatus.InvalidPassword:
        // Password is incorrect. Please try again.
        break;
    case AccountStatus.ExpiredPassword:
        // Password has expired. Please reset your password.
        break;
    case AccountStatus.MustChangePassword:
        // Account flagged as 'User must change password at next log on.';
        break;
    case AccountStatus.UserLockedOut:
        // Account is locked. Contact IT to unlock your account.
        break;
    case AccountStatus.UserNotFound:
        // Account does not exist in Active Directory.
        break;
    case AccountStatus.Success:
        // Password is correct, so do stuff
		if (!IsRegistered(user.ObjectGuid))
    		Register(user.ObjectGuid, user.DisplayName, user.Email);
        break;
}
```

## Why?
Here at [Western Digital](http://wdc.com), each employee has an account in [Active Directory](https://en.wikipedia.org/wiki/Active_Directory) they use to sign into Windows. Most of our apps query Active Directory as a means to authenticate users and read attributes about the user such as name, email, and city.

We found our developers were often reinventing the wheel, so this library is an attempt to consolidate our efforts by making a C# wrapper that is type safe and easy to use.

## Building
Requirements:

* Visual Studio 2015 (VS 2010+ will work)
* Target Framework .NET 3.5

Run `msbuild Wdc.DirectoryLib.csproj` to build as Release.

## Packaging
1. Increment `<version>` and update `<releaseNotes>` in the `.nuspec` file
2. Download `nuget.exe` from http://nuget.org
3. Run `nuget pack Wdc.DirectoryLib.csproj` to build and generate `.nupkg` file
4. Upload the new package to nuget.org
5. Zip binaries and attach to [GitHub releases](https://github.com/westerndigitalcorporation/DirectoryLib/releases)

## Contributing
Pull requests are welcome! We currently do not have any public tests available, but send us a pull request and we'll try it out and merge it in.

## License
MIT
# DirectoryLib
A wrapper library for Active Directory (LDAP) authentication in .NET

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
Building requires Visual Studio 2010 or better. We are using Visual Studio 2015. Alternatively, you can use `msbuild` on the command line.

The Target Framework is .NET 3.5 so it will work in legacy 2.0 runtime or the newer 4.0 runtime.

## Packaging
1. Increment version in the `.nuspec` file
2. Download `nuget.exe` from http://nuget.org
3. Run `nuget.exe pack Wdc.DirectoryLib.csproj` which will build as Release and create a `.nupkg` file
4. Upload the new package to nuget.org

## Contributing
Pull requests are welcome! We currently do not have any public tests available, but send us a pull request and we'll try it out and merge it in.

## License
MIT
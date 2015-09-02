# DirectoryLib
A wrapper library for Active Directory (LDAP) Authentication in C#.

## Usage
```cs
Context context = new Context("domain-controller.example.com");
UserAccount user = context.GetUserByUpn("johnson_j@net.example.com");
AccountStatus status = context.Authenticate(user, "secure-password-123");

switch (status)
{
    case AccountStatus.PASS_INCORRECT:
        // Password is incorrect. Please try again.
        break;
    case AccountStatus.PASS_EXPIRED:
        // Password has expired. Please reset your password.
        break;
    case AccountStatus.PASS_MUST_CHANGE:
        // Account flagged as 'User must change password at next log on.';
        break;
    case AccountStatus.USER_LOCKED_OUT:
        // Account is locked. Contact IT to unlock your account.
        break;
    case AccountStatus.USER_NOT_FOUND:
        // Account does not exist in Active Directory.
        break;
    case AccountStatus.PASS_CORRECT:
        // Password is correct, so do stuff
		if (!IsRegistered(user.ObjectGuid))
    		Register(user.ObjectGuid, user.DisplayName, user.Email);
        break;
}
```

## Why?
Here at [WD](http://wdc.com), each employee has an account in [Active Directory](https://en.wikipedia.org/wiki/Active_Directory) they use to sign into Windows. Most of our apps query Active Directory as a means to authenticate users and read attributes about the user such as name, email, and city.

We found our developers were often reinventing the wheel, so this library is an attempt to consolidate our efforts by making a C# wrapper that is type safe and easy to use.

## Contributing
Pull requests are welcome! We currently do not have any public tests available, but send us a pull request and we'll try it out and merge it in.

## License
MIT
LdapAuthenticator for Nette
===========================
The LDAP/Active Directory authenticator plugin for Nette Framework.

Supported out of the box:
- LDAP Authentication (obviously)
- User information loading, including user picture in AD
- User groups membership, **including group inheritance.** (*groupA member of groupB, which is member of groupC? No problem!*)
- Groups whitelist for login (aka "allowLogin")
- Groups blacklist for login (aka "refuseLogin")
- Admin role appender - user will have "admin" role, if he's present in some of the specified LDAP groups
- Groups-to-roles mapping based on group DN, name and/or e-mail address
- Post-processing data **before** identity creation based on [Callbacks](#callback-options)
	- used for loading of user database id and more
- [Identity generator](#identity-generator) from loaded data, based on callback - don't like default behaviour? Rewrite it!
- [Username generator](#username-generator) based on callback - following logins are valid by default:
	- name.surname
	- name.surname@yourdomain.com
- [Success login handlers](#success-handlers) for integrating the LDAP into your application. In example, this is used for both
  userdata loading from LDAP (thumbnails, name & surname, etc.),  **and** for loading the ID from database (so that
  your database model can work seamlessly with LDAP.)

Include once, extend forever. Under MIT license.

Install
-------
```
$ composer require foglcz/ldap-authenticator --no-dev
```

Use
---
1. Open `app/model/UserManager.php` and **remove** the `implements Nette\Security\IAuthenticator`
2. Open `app/config/config.neon` file and change default `UserManager` definition.

	```
	services:
		- App\Model\UserManager
	```

	becomes:

	```
	services:
		userManager: App\Model\UserManager
	```

3. Open `app/config/config.neon` file and **add** following to `services` and `parameters` sections:

	```
	parameters:
		ldap:
			hostname: 'xxx.xxx.xxx.xxx'  # your LDAP server ip
			port: 3268					 # your LDAP server port (if different than default)
			baseDn: 'DC=domain,DC=local' # your LDAP base DN search - usually change this to your domain.tld
			loadGroups: true 		     # set to false if you don't want the auto groups loading & roles loading

	services:
		authenticator:
			class: foglcz\ldap\Authenticator(%ldap%, "yourcompany.com", "yourcomany.local") # Third parameter optional, used if you have different e-mail domains than the AD domain.
			setup:
				- addSuccessHandler('id', [@userManager, 'getAuthId'])
	```

4. Add following method into your `UserManager` class:

	```php
	/**
	 * Success handler for LDAP authenticator - loads the ID in database
	 *
	 * @param \Toyota\Component\Ldap\Core\Manager $ldap
	 * @param array $userData
	 * @throws Security\AuthenticationException
	 * @return int
	 */
	public function getAuthId(\Toyota\Component\Ldap\Core\Manager $ldap, array $userData)
	{
		$username = 'ldap/' . $userData['username'];
		if($user = $this->database->table('user')->where('username = ?', $username)->fetch()) {
			return $user->id;
		}

		return $this->database->table('user')->insert(array('username' => $username));
	}
	```

	The getAuthId function returns id of the identity, that gets generated - therefore, in rest of your application,
	you can freely use `$user->id` for relations etc.

Authentication flow
-------------------
Essentially, the whole LDAP Authenticator is built on top of callbacks. This means that in most cases, you don't need
to extend the class and/or make use of it in your authenticator. Instead, you'd "plug-in" your callbacks to do the work
as it's needed in your particular project.

The authentication flow is as follows:

1. `$user->login(username, password);`
2. Post-process the given username. By default, we strip out the domain parameter (see below) of the constructor, and
	replace it with FQDN. Therefore, you can have "yourdomain.local" Active Directory forrest, while logging in with
	the "email@yourdomain.com" usernames - or just with "email" part of the login. See [Callbacks section](#callback-options)
	for more details
3. Connect to LDAP server as specified in the configuration - the library [tiesa/ldap](https://github.com/ccottet/ldap)
    is used for this purpose
4. Bind the given username to the domain, effectively authenticating against the LDAP. User is bind in format of
 	username@fqdn , so in your case it might be username@yourdomain.local
5. If no exception is thrown, $userData array is created with following attributes:

	```
	array (2)
		username => "name.surname" (6)
		fqdn => "yourdomain.local" (14)
	```
6. Loop through success handlers. By default this in-loads User Data information from LDAP, and in-loads the groups
	memberships. **Group inheritance is supported**, so if user is a part of groupA, which is a part of groupB, **both**
	will show up in the memberships.

	Note that here, your registered callbacks are called as well:

	```
	array (8)
		username => "name.surname" (6)
		fqdn => "yourdomain.local" (14)
		userinfo => array (10)
			lastName => "Surname | COMPANY" (17)
			firstName => "Name" (5)
			department => "IT" (2)
			company => "Yourcompany" (15)
			proxyAddresses => array (2)
				0 => "SMTP:name.surname@yourcompany.com" (30)
				1 => "smtp:nsurname@yourdomain.com" (25)
			fullName => "Name Surname | COMPANY" (23)
			changePasswordOnLogon => "000000000000000000" (18)
			UPN => "name.surname@yourdomain.local" (27)
			mail => "name.surname@yourdomain.com" (25)
			manager => "CN=Some One,OU=CS,OU=SBSUsers,OU=Users,OU=MyBusiness,DC=yourdomain,DC=local" (85)
		memberOf => array (16)
			"CN=DL Decision makers,OU=Distribution Groups,OU=MyBusiness,DC=yourdomain,DC=local" => array (3)
				dn => "CN=DL Decision makers,OU=Distribution Groups,OU=MyBusiness,DC=yourdomain,DC=local" (82)
				name => "DL Decision makers" (21)
				mail => "decisions" (12)
	```

7. Check whether the user is in any of the groups that are either allowed or refused to login. Throw exception when
	user is not allowed to login.
8. Call identity provider and give back the identity returned. For definition, see [Identity generator](#identity-generator) section.

Most of these are built-in, enabled and disabled by altering the configuration (see below.)

Configuration options
---------------------
Configuration is done within `config.neon` file. By default, the authenticator is pretty extensible by configuration.

```
parameters:
	ldap:
		hostname: 'xxx.xxx.xxx.xxx'
		port: 3268
		baseDn: 'DC=yourcompany,DC=com' # Base searchpath within your LDAP
		loadGroups: true            # By default on, turn off if you don't want to load groups
		refuseLogin: ['DL USA']     # Either group FQDN's, names and/or e-mail addresses || refused
		allowLogin:  ['DL VPN']     # Either group FQDN's, names and/or e-mail addresses || null == pustit vsechny krome refuse
		loadRolesAsMailGroups: true # By default off (false/not defined). If on, the group e-mails will be used as roles of the given user
		rolesMap:                   # see below
			VPN_FG: vpn
			"DL Property": "property"
		adminGroups: ['VPN_FG', 'Administrators'] # add "admin" role if present in the list of roles. Groups can be specified as FQDN's, names and/or e-mail addresses.
```

#### Allow / refuse logic ####

The authenticator employs refuse-first authentication principle. If you define both allow login & refuse login, members
of refuse groups will be always refused, regardless of whether they are member of allowed groups.

If you define only `refuseLogin` parameter, all users will be logged in *unless* they are member of refused groups.

If you define only `allowLogin` parameter, all users that are not members of at least one of the allowed groups, will be
refused.

Exceptions
----------
Authenticator throws following exceptions:

- `class UserInRefuseGroupException extends \foglcz\LDAP\AuthenticationException`
  Thrown when user is a member of `refuseLogin` groups. Default message is "Members of XXX are not allowed to login."

- `class UserNotInAllowedGroupException extends \foglcz\LDAP\AuthenticationException`
  Thrown when you define `allowLogin` parameter, and the user is not in any of the specified groups. Note that if you
  also defined refuseLogin groups, this gets thrown **only** when the user is not a member of those refuse groups
  (we employ refuse-first policy.) The message is: "You are not member of allowed groups that can login."

- `class PossibleConfigurationErrorException extends AuthenticationException`
  Thrown **only** when you forcefully turn off loadGroups parameter, but still employ functionality, which is dependant
  on the groups loading. These are allowLogin, refuseLogin, adminGroups, loadRolesAsMailGroups and rolesMap. **Note**:
  The exception is not thrown when you turn off groups loading, but set your own `memberOf` success handler.

- `class AuthenticationException extends \Nette\Security\AuthenticationException`
  Thrown when user is, in fact, not allowed to login (the bind against LDAP failed.) Note that we use simple
  "Username or password is not valid" message.


Note that we throw *our* `AuthenticationException`, since we want to make it easy to catch LDAP errors in case you have
multiple authenticators like we do.

You can implement `try {} catch {}` for rewriting the error messages based on context. If you want to catch simply all
of them, feel free to catch `\Nette\Security\AuthenticationException` directly.

Callback options
----------------
As you can see from the authentication flow, the LdapAuthenticator is very extensible by default, thanks to callbacks.

The callbacks setup is done via class functions, so that it's easy to configure in `config.neon` as you can see below:

```
authenticator:
	class: foglcz\ldap\Authenticator(%ldap%, "comodo.com", "comodo.local")
	setup:
		- setUsernameGenerator([@userModel, 'authGetUsername'])
		- removeSuccessHandler('memberof')
		- addSuccessHandler('memberof', [@userModel, 'getMemberOf'])
		- addSuccessHandler('thumbnail', [\foglcz\LDAP\Success\ThumbnailLoader, 'getThumbnail'])
		- setIdentityGenerator([@userModel, 'authGenerateIdentity'])
```

#### Success handlers ####

Success handlers are used to in-load more information to the `$userData` array. The userData is then used within
Identity generator, as a third parameter of generated identity.

Default success handler is described in [top section](#use) and returns data, which will be saved within `$userData`
under specified key. Registration function takes two parameters:

1. Key under which to store function result
2. Callback which is called with parameters `Manager` and `$userData`.

The success handlers constains no magic, and can be used for effectively anything you want.

#### Identity generator ####

The identity generator is used to generate an `\Nette\Security\Identity` class from the given `$userData`, which can
be extended by SuccessHandlers as seen above. The default identity generator looks up presence of `$userData['memberOf']`
parameter, to in-load the roles. The default identity generator also appends `admin` role if user is present within
admin groups as defined in config.

Piece of sourcecode is worth a thousand words. Default identity generator looks like this:

```php
public function createIdentity(Toyota\Component\Ldap\Core\Manager $ldap, array $userData)
{
	$roles = array();
	if(!isset($userData['memberOf'])) {
		throw new PossibleConfigurationErrorException('User\'s memberOf index is not set; maybe reset default groups handler?');
	}

	// Load roles based on membership if needed
	if(isset($this->config['loadRolesAsMailGroups'])) {
		$roles = array_merge($roles, $this->loadRoleMailsFromGroups($userData));
	}

	// Load roles mapping if set
	if(isset($this->config['rolesMap'])) {
		$roles = array_merge($roles, $this->loadRoleMapping($userData));
	}

	// In-load admin groups if requested
	if(isset($this->config['adminGroups']) && !in_array('admin', $roles) && $this->loadIsAdminMember($userData)) {
		$roles[] = 'admin';
	}

	// Create identity & return
	return new Identity(isset($userData['id']) ? $userData['id'] : $userData['username'], $roles, $userData);
}
```

#### Username generator ####

The username generator takes any user-supplied input and transforms it into LDAP-valid username. In general, we have
two scenarios which we can find in the wild:

1. The AD Forrest name is **same** as user e-mail domain (forrest name is `yourcompany.com`
2. The AD Forrest name is **different** than user e-mail domain (forrest name is `yourcompany.local`

Default username generator takes care of both. This is also a reason for three parameters constructor of Authenticator.

What we wanted to do, is to enable our users to login either with `name.surname` and/or with `name.surname@yourcompany.com`,
while having *different* forrest name. By default, the username generator takes the user-supplied input, strips off the
`@yourcompany.com` part (if present), and appends `@yourcompany.local` part.

The returned username is then used for authentication within LDAP.

#### Generator common usage ####
The default common usage of username generator would be to take the username, and prepend the pre-2000 authentication
domain. To use it, we would define following function in our `UserManager` class:

```php
public function createUsername(Manager $ldap, $username)
{
	return 'yourdomain\' . $username;
}
```

In order to use this generator, following should be added to `setup` part within `config.neon`:

```
authenticator:
	class: foglcz\ldap\Authenticator(%ldap%, "whatever")
	setup:
		- setUsernameGenerator([@userModel, 'createUsername'])
```

Extend with your class
----------------------
There is little need to extend the default authenticator by yours, but thats entirely possible. You just need to
remember, that in `config.neon services:` section you can have **only one Authenticator** - that means that if you
extend the `\foglcz\LDAP\Authenticator`, you also need to remove it from your project's config.neon.

Contribute
----------
Licensed under MIT license. Full text of license available in `LICENSE.md` file.

Feel free to fork! I grant write access to the repository to pull requests authors, if their changes makes sense for
the project. I believe that with this approach, we can make sure that the pull request is highest quality, since it's
always merged by the author of the pull request - not by the author of repository. Note: the repository write access is
not revoked after merge.

Originally created by Pavel `@foglcz` Ptacek, (c) 2014

Contributors so far
- Pavel Ptacek
- YOU!

[Fork me!](https://github.com/foglcz/ldap-authenticator/fork)
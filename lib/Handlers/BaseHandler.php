<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP\Success;

/**
 * Base handler with cache
 *
 * @package foglcz\LDAP\Success
 */
abstract class BaseHandler
{

	/** @var string Lookup string for finding users in LDAP. This is pre-2000 field in most of Active Directories. */
	public static $UserLookup = '(|(userprincipalname=:upn:)(sAMAccountName=:username:))';

}
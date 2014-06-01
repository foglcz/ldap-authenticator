<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP;
use foglcz\LDAP\Success\BaseHandler;

/**
 * Utilities used throughout the package
 * @package foglcz\LDAP
 */
class Utils
{
    /**
     * Load group name from DN
     *
     * @param string $dn
     * @return string
     */
    public static function loadNameFromDn($dn)
    {
        $name = '';
        $dn = explode(',', $dn);
        foreach ($dn as $one) {
            if (strpos($one, 'CN=') === false) {
                continue;
            }

            $parts = explode('=', $one);
            $name = $parts[1];
            break;
        }

        return $name;
    }

	/**
	 * Get full user lookup string
	 *
	 * @param string $username
	 * @return string
	 */
	public static function getUserLookup($username)
	{
		$search = array(':upn:', ':username:');
		$replace = array($username);

		// Post-process username: remove "domain\" and "@upn" parts
		if(strpos($username, '\\') !== false) {
			$username = substr($username, strpos($username, '\\') + 1);
		}
		if(strpos($username, '@') !== false) {
			$username = substr($username, 0, strpos($username, '@'));
		}

		$replace[] = $username;

		return str_replace($search, $replace, BaseHandler::$UserLookup);
	}
}
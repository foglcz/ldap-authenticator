<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP;

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
}
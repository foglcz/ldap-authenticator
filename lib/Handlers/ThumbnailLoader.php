<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP\Success;

use Toyota\Component\Ldap\Core\Manager;
use Toyota\Component\Ldap\Core\Node;
use Toyota\Component\Ldap\Core\NodeAttribute;


/**
 * Loads thumbnail for the user
 * @package foglcz\LDAP\SuccessHandlers
 */
class ThumbnailLoader extends BaseHandler
{

    /**
     * Load thumbnail and save it's base64 in userdata
     * @param Manager $ldap
     * @param array $userData
     * @return string|false
     */
    public static function getThumbnail(Manager $ldap, array $userData)
    {
        $username = $userData['username'];

        $raw = $ldap->search(null, str_replace(':username:', $username, self::$UserLookup), true, array('thumbnailphoto'));
        if(!$raw->current() instanceof Node) {
            return false;
        }

        /** @var NodeAttribute[] $attrs */
        $attrs = $raw->current()->getAttributes();

        // Load user image
        if (empty($attrs['thumbnailPhoto']) !== true && $attrs['thumbnailPhoto']->getValues()) {
            $img = $attrs['thumbnailPhoto']->getValues();
            return 'data:image/jpg' . ';base64,' . base64_encode($img[0]);
        }

        return false;
    }
}
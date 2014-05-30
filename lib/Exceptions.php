<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP;

/**
 * LDAP Authentication exception
 *
 * @package foglcz\LDAP
 */
class AuthenticationException extends \Nette\Security\AuthenticationException
{}

/**
 * Internal exception that should be caught, since this SHOULD be a configuration error
 * @package foglcz\LDAP
 */
class PossibleConfigurationErrorException extends AuthenticationException
{}

/**
 * Thrown when user is a member of refuseLogin group.
 * @package foglcz\LDAP
 */
class UserInRefuseGroupException extends AuthenticationException
{}

/**
 * Thrown when user is not a member of allowedLogin groups.
 * @package foglcz\LDAP
 */
class UserNotInAllowedGroupException extends AuthenticationException
{}
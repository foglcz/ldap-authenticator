<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP\Success;

use foglcz\LDAP\Utils;
use Toyota\Component\Ldap\Core\Manager;
use Toyota\Component\Ldap\Core\Node;
use Toyota\Component\Ldap\Core\NodeAttribute;

/**
 * Static user information loader
 * @package foglcz\LDAP\Success
 */
class UserInfoLoader extends BaseHandler
{
	/** @var array of information loadings */
	private $loadInfo;

	/**
	 * @param array $loadInfo (ldapKey => applicationKey) | the applicationKey is used for returning data
	 * @see http://www.computerperformance.co.uk/Logon/LDAP_attributes_active_directory.htm
	 */
	public function __construct($loadInfo = null)
	{
		$this->loadInfo = is_array($loadInfo) ? $loadInfo : array(
			// Useful attributes
			'givenName' => 'firstName',
			'sn' => 'lastName',
			'name' => 'fullName',
			'mail' => 'mail',
			'company' => 'company',
			'streetAddess' => 'street',
			'l' => 'city',
			'postalCode' => 'zip',
			'c' => 'country',
			'st' => 'state',

			'mobile' => 'mobile',
			'manager' => 'manager',
			'department' => 'department',

			// LDAP attributes
			'sAMAccountName' => 'sAMAccountName',
			'userPrincipalName' => 'UPN',
			'proxyAddresses' => 'proxyAddresses',
			'location' => 'ldapLocation',
			'pwdLastSet' => 'changePasswordOnLogon',
		);
	}

	/**
	 * Load data as per constructor instance
	 *
	 * @param Manager $ldap
	 * @param array $userData
	 * @return array
	 */
	public function getUserInfo(Manager $ldap, array $userData)
	{
		// Load
		$raw = $ldap->search(null, Utils::getUserLookup($userData['username']), true, array_keys($this->loadInfo));
		if(!$raw->current() instanceof Node) {
			return array();
		}
		$attrs = $raw->current()->getAttributes();

		// Post process & return
		$return = array();
		foreach($attrs as $key => $val) {
			/** @var NodeAttribute $val */
			$rkey = $this->loadInfo[$key];
			$return[$rkey] = $val->getValues();
			if(count($return[$rkey]) === 1) {
				$return[$rkey] = reset($return[$rkey]);
			}
		}

		return $return;
	}
}
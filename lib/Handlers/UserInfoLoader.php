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
	/** @var array of information that should be loaded */
	private $loadInfo;

	/**
	 * @param array $loadInfo (ldapKey => applicationKey) | the applicationKey is used for returning data
	 * @see http://www.computerperformance.co.uk/Logon/LDAP_attributes_active_directory.htm
	 */
	public function __construct($loadInfo = NULL)
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
			'objectSid' => 'objectSid',

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
		$raw = $ldap->search(NULL, Utils::getUserLookup($userData['username']), TRUE, array_keys($this->loadInfo));
		if (!$raw->current() instanceof Node) {
			return array();
		}
		$attributes = $raw->current()->getAttributes();

		// Post process & return
		$return = array();
		foreach ($attributes as $key => $value) {
			/** @var NodeAttribute $value */
			$newKey = $this->loadInfo[$key];

			if ($key == 'objectSid') {
				$return[$newKey] = array($this->getObjectSidFromBinary($value->getValues()[0]));
			} else {
				$return[$newKey] = $value->getValues();
			}

			if (count($return[$newKey]) === 1) {
				$return[$newKey] = reset($return[$newKey]);
			}
		}

		return $return;
	}

	/**
	 * @param string $binSid
	 * @return string Returns the textual SID
	 */
	private function getObjectSidFromBinary($binSid)
	{
		$hex_sid = bin2hex($binSid);
		$rev = hexdec(substr($hex_sid, 0, 2));
		$subCount = hexdec(substr($hex_sid, 2, 2));
		$auth = hexdec(substr($hex_sid, 4, 12));
		$result = "$rev-$auth";

		for ($x = 0; $x < $subCount; $x++) {
			$subAuth[$x] =
				hexdec($this->getLittleEndian(substr($hex_sid, 16 + ($x * 8), 8)));
			$result .= "-" . $subAuth[$x];
		}

		// Cheat by tacking on the S-
		return 'S-' . $result;
	}

	/**
	 * Converts a little-endian hex-number to one, that 'hexdec' can convert
	 *
	 * @param string $hex
	 * @return string
	 */
	private function getLittleEndian($hex)
	{
		$result = '';
		for ($x = strlen($hex) - 2; $x >= 0; $x = $x - 2) {
			$result .= substr($hex, $x, 2);
		}

		return $result;
	}
}

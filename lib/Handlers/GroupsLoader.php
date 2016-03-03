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
 * Handlers class for authenticator itself
 *
 * @package foglcz\LDAP\Success
 */
class GroupsLoader extends BaseHandler
{

	/** @var string Lookup string for all groups in the system */
	public static $GroupLookup = '(&(objectClass=Group))';

	/** @var string Finds all groups that given group is a member of */
	public static $GroupMemberOfLookup = '(&(objectClass=group)(member=:group:))';

	/**
	 * @param Manager $ldap
	 * @param array $userData
	 * @return array
	 */
	public function getUserGroups(Manager $ldap, array $userData)
	{
		$allGroups = $this->loadAllGroups($ldap, $userData);
		$memberOf = $this->getUserMemberOf($ldap, $userData, $allGroups);

		// Merge the two and return
		foreach($memberOf as $dn => $name) {
			if(!isset($allGroups[$dn])) {
				continue;
			}

			$memberOf[$dn] = $allGroups[$dn];
		}

		return $memberOf;
	}

	/**
	 * Load all groups in the system - 1 LDAP query
	 *
	 * @param Manager $ldap
	 * @return array (groupDn => array(dn, name, mail))
	 */
	protected function loadAllGroups(Manager $ldap)
	{
		$groups = array();

		$raw = $ldap->search(null, self::$GroupLookup);
		foreach ($raw as $group) {
			/** @var $group \Toyota\Component\Ldap\Core\Node */
			$groupDn = $group->getDn();
			if (!isset($groups[$groupDn])) {
				$groups[$groupDn] = array(
					'dn' => $groupDn,
					'name' => Utils::loadNameFromDn($groupDn),
					'mail' => '',
				);
			}

			// Load group mail if present
			if ($group->get('mail')) {
				$mail = $group->get('mail')->getValues();
				$mail = $mail[0];
				$mail = substr($mail, 0, strpos($mail, '@')); // only the part before @
			} else {
				$mail = false;
			}
			$groups[$groupDn]['mail'] = $mail;
		}

		return $groups;
	}

	/**
	 * Load memberOf for the current user - 1 LDAP query
	 *
	 * @param Manager $ldap
	 * @param array $userData
	 * @param array $allowedGroups
	 * @return array (groupDn => groupName)
	 */
	protected function getUserMemberOf(Manager $ldap, array $userData, array $allowedGroups)
	{
		$memberOf = array();
		$processed = array();
		$iterator = new \SplQueue();
		$iterator->setIteratorMode(\SplQueue::IT_MODE_DELETE);

		// Load membership
		$raw = $ldap->search(null, Utils::getUserLookup($userData['username']), true, array('memberof'));
		if(!$raw->current() instanceof Node) {
			return array();
		}
		$attrs = $raw->current()->getAttributes();
		if(!array_key_exists('memberOf', $attrs) || !$attrs['memberOf'] instanceof NodeAttribute) {
			return array();
		}

		// Post process all groups into memberOf array, put them into iterator for inheritance loading
		foreach($attrs['memberOf'] as $groupDn) {
			$memberOf[$groupDn] = Utils::loadNameFromDn($groupDn);
			if(isset($processed[$groupDn])) {
				continue;
			}

			$iterator->enqueue($groupDn);
			$processed[$groupDn] = true;
		}

		// Loop iterator & load all inherits
		while(!$iterator->isEmpty()) {
			$groupDn = $iterator->dequeue();
			$inherits = $this->getGroupMemberOf($ldap, $groupDn);
			foreach($inherits as $one) {
				/** @var Node $one */
				if(isset($processed[$one->getDn()])) {
					continue;
				}

				$processed[$one->getDn()] = true;
				$iterator->enqueue($one->getDn());
				$memberOf[$one->getDn()] = Utils::loadNameFromDn($one->getDn());
			}
		}

		return $memberOf;
	}

	/**
	 * @param Manager $ldap
	 * @param $groupDn
	 * @return Node[]|false
	 */
	protected function getGroupMemberOf(Manager $ldap, $groupDn)
	{
		return $ldap->search(null, str_replace(':group:', ldap_escape($groupDn, null, LDAP_ESCAPE_DN), self::$GroupMemberOfLookup));
	}
}



if (!function_exists('ldap_escape')) {
	//from: http://stackoverflow.com/questions/8560874/php-ldap-add-function-to-escape-ldap-special-characters-in-dn-syntax
	define('LDAP_ESCAPE_FILTER', 0x01);
	define('LDAP_ESCAPE_DN', 0x02);


	/**
	 * @param string $subject The subject string
	 * @param string $ignore Set of characters to leave untouched
	 * @param int $flags Any combination of LDAP_ESCAPE_* flags to indicate the
	 *                   set(s) of characters to escape.
	 * @return string
	 */
	function ldap_escape($subject, $ignore = '', $flags = 0)
	{
		static $charMaps = array(
			LDAP_ESCAPE_FILTER => array('\\', '*', '(', ')', "\x00"),
			LDAP_ESCAPE_DN => array('\\', ',', '=', '+', '<', '>', ';', '"', '#'),
		);

		// Pre-process the char maps on first call
		if (!isset($charMaps[0])) {
			$charMaps[0] = array();
			for ($i = 0; $i < 256; $i++) {
				$charMaps[0][chr($i)] = sprintf('\\%02x', $i);
				;
			}

			for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_FILTER]); $i < $l; $i++) {
				$chr = $charMaps[LDAP_ESCAPE_FILTER][$i];
				unset($charMaps[LDAP_ESCAPE_FILTER][$i]);
				$charMaps[LDAP_ESCAPE_FILTER][$chr] = $charMaps[0][$chr];
			}

			for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_DN]); $i < $l; $i++) {
				$chr = $charMaps[LDAP_ESCAPE_DN][$i];
				unset($charMaps[LDAP_ESCAPE_DN][$i]);
				$charMaps[LDAP_ESCAPE_DN][$chr] = $charMaps[0][$chr];
			}
		}

		// Create the base char map to escape
		$flags = (int)$flags;
		$charMap = array();
		if ($flags & LDAP_ESCAPE_FILTER) {
			$charMap += $charMaps[LDAP_ESCAPE_FILTER];
		}
		if ($flags & LDAP_ESCAPE_DN) {
			$charMap += $charMaps[LDAP_ESCAPE_DN];
		}
		if (!$charMap) {
			$charMap = $charMaps[0];
		}

		// Remove any chars to ignore from the list
		$ignore = (string)$ignore;
		for ($i = 0, $l = strlen($ignore); $i < $l; $i++) {
			unset($charMap[$ignore[$i]]);
		}

		// Do the main replacement
		$result = strtr($subject, $charMap);

		// Encode leading/trailing spaces if LDAP_ESCAPE_DN is passed
		if ($flags & LDAP_ESCAPE_DN) {
			if ($result[0] === ' ') {
				$result = '\\20' . substr($result, 1);
			}
			if ($result[strlen($result) - 1] === ' ') {
				$result = substr($result, 0, -1) . '\\20';
			}
		}

		return $result;
	}
}

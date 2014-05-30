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
        $raw = $ldap->search(null, str_replace(':username:', $userData['username'], self::$UserLookup), true, array('memberof'));
        if(!$raw->current() instanceof Node) {
            return array();
        }
        $attrs = $raw->current()->getAttributes();
        if(!$attrs['memberOf'] instanceof NodeAttribute) {
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
        return $ldap->search(null, str_replace(':group:', $groupDn, self::$GroupMemberOfLookup));
    }
}
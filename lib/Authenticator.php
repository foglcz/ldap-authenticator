<?php
/**
 * This file is part of foglcz/LdapAuthenticator package.
 *
 * @license MIT
 * @author Pavel Ptacek
 */
namespace foglcz\LDAP;

use foglcz\LDAP\Success\GroupsLoader;
use foglcz\LDAP\Success\UserInfoLoader;
use Nette\Object;
use Nette\Security\AuthenticationException;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;
use Nette\Utils\Arrays;
use Nette\Utils\Strings;
use Toyota\Component\Ldap\Core\Manager;
use Toyota\Component\Ldap\Platform\Native\Driver;
use Toyota\Component\Ldap\Exception\BindException;


/**
 * Base authenticator for LDAP
 *
 * @package foglcz\ldap
 */
class Authenticator extends Object implements IAuthenticator
{
    /**
     * The username generator from user supplied input. By default, this stripps down the e-mail part -- in example,
     * you can have LDAP usernames as firstname.lastname@company.com , but usernames as <first name letter><lastname>@company.com .
     * If that's the case, use this handler to generate yours username
     *
     * @var Callable username generator from supplier email/whatever
     */
    public $usernameGenerator;

    /**
     * Success handlers to in-load additional data / postprocess before identity creation
     *
     * @var Callback[]
     */
    public $onSuccess = array();

    /**
     * The identity generator callback. Used for generating identity from given data, that were post-processed by success handlers
     *
     * @var Callable
     */
    public $identityGenerator;

    /** @var array */
    private $config;

    /** @var Manager */
    private $ldap;

    /** @var string e-mail domain, not LDAP domain */
    private $domain;

    /** @var string LDAP domain, not email domain */
    private $fqdn;

    /** @var UserInfoLoader */
    private $userInfoLoader;

    /** @var GroupsLoader */
    private $groupsLoader;

    /**
     * @param array $config
     * @param string $domain
     * @param string $fqdn
     * @param Manager $manager
     */
    public function __construct(array $config, $domain, $fqdn = '', Manager $manager = null)
    {
        $this->domain = $domain;
        $this->fqdn = (!empty($domain) && empty($fqdn)) ? $domain : $fqdn;
        (empty($this->fqdn)) ? : $this->fqdn = '@' . $this->fqdn;

        // Ldap setter
        isset($config['baseDn']) ? $config['base_dn'] = $config['baseDn'] : null;
        isset($config['bindDn']) ? $config['bind_dn'] = $config['bindDn'] : null;
        isset($config['bindPassword']) ? $config['bind_password'] = $config['bindPassword'] : null;

        // Load default dependencies, groups loader is optional
        $this->ldap = $manager ?: new Manager($config, new Driver());
        $this->userInfoLoader = new UserInfoLoader();

        // Default callbacks
        $this->setUsernameGenerator(array($this, 'createUsername'));
        $this->setIdentityGenerator(array($this, 'createIdentity'));
        $this->addSuccessHandler('userinfo', array($this->userInfoLoader, 'getUserInfo'));

        // Load groups by default based on config. If not set, check whether there are other dependant rules
        $config['loadGroups'] = isset($config['loadGroups']) ?
                                    $config['loadGroups'] :
                                    array_intersect(array_keys($config), array('allowLogin', 'refuseLogin', 'adminGroups', 'loadRolesAsMailGroups', 'rolesMap'));
        if($config['loadGroups']) {
            $this->groupsLoader = new GroupsLoader();
            $this->addSuccessHandler('memberOf', array($this->groupsLoader, 'getUserGroups'));
        }

        // Save config
        $this->config = $config;
    }

    /**
     * @param callable $handler <string>function(Toyota\Component\Ldap\Core\Manager, $username)
     */
    public function setUsernameGenerator(Callable $handler)
    {
        $this->usernameGenerator = $handler;
    }

    /**
     * @param string $dataKey $userData[$dataKey] = return of the callback
     * @param Callable $handler <void>function(Toyota\Component\Ldap\Core\Manager, $userData)
     */
    public function addSuccessHandler($dataKey, Callable $handler)
    {
        $this->onSuccess[$dataKey] = $handler;
    }

    /**
     * @param string $dataKey data key to be removed
     */
    public function removeSuccessHandler($dataKey)
    {
        unset($this->onSuccess[$dataKey]);
    }

    /**
     * @param callable $handler <IIdentity>function(Toyota\Component\Ldap\Core\Manager, $userData)
     */
    public function setIdentityGenerator(Callable $handler)
    {
        $this->identityGenerator = $handler;
    }

    /**
     * Perform auth against ldap
     *
     * @param array $credentials
     * @return Identity|\Nette\Security\IIdentity
     * @throws \Nette\Security\AuthenticationException
     */
    public function authenticate(array $credentials)
    {
        list($username, $password) = $credentials;
        $username = call_user_func_array($this->usernameGenerator, array($this->ldap, $username));

        // Auth
        try {
            $this->ldap->connect(); // @todo: Pullrequest to toyota, to check whether we're already connected
            $this->ldap->bind($username . $this->fqdn, $password);
            $data = array(
                'username' => $username,
                'fqdn' => Strings::substring($this->fqdn, 1),
            );
        } catch (BindException $e) {
            throw new AuthenticationException('Username or password is not valid', $e->getCode(), $e);
        }

        // Success handlers
        foreach ($this->onSuccess as $key => $handler) {
            $data[$key] = $handler($this->ldap, $data);
        }

        // Allow/refuse login based on groups
        $this->assertHasGroupAccess($data);

        // Get & return the identity
        return call_user_func_array($this->identityGenerator, array($this->ldap, $data));
    }

    /**
     * Default username generator. Allows for logins via both username and e-mail against the FQDN
     *
     * @param Manager $ldap
     * @param string $username
     * @return string
     */
    public function createUsername(Manager $ldap, $username)
    {
        $username = Strings::trim(Strings::lower($username));
        $domain = '@' . Strings::trim(Strings::lower($this->domain));

        if (Strings::endsWith($username, $domain)) {
            $username = Strings::substring($username, 0, strpos($username, $domain));
        }

        return $username;
    }

    /**
     * Allow / refuse login based on config
     *
     * @param array $userData
     * @throws AuthenticationException
     */
    public function assertHasGroupAccess(array $userData)
    {
        if($this->config['loadGroups'] && !isset($userData['memberOf'])) {
            throw new PossibleConfigurationErrorException('LDAP did not load any memberships (even empty ones) for this user. Make sure you return groups into "memberOf" key of userdata.');
        }
        if(!isset($userData['memberOf'])) {
            return; // Do nothing when groups are not loaded in
        }

        $memberOf = Arrays::flatten($userData['memberOf']);
        $refuse = array_intersect($memberOf, isset($this->config['refuseLogin']) ? $this->config['refuseLogin'] : array());
        $allow = array_intersect($memberOf, isset($this->config['allowLogin'])  ? $this->config['allowLogin']  : array());

        // If there's ANYTHING in $refuse intersect, user is not allowed since this is a blacklist
        if(!empty($refuse)) {
            throw new UserInRefuseGroupException('Members of ' . reset($refuse) . ' are not allowed to login.');
        }

        // If there's NOTHING in $allow intersect, user is not allowed since this is a whitelist
        if(empty($allow) && isset($this->config['allowLogin'])) {
            throw new UserNotInAllowedGroupException('You are not member of allowed groups that can login.');
        }
    }

    /**
     * @param Manager $ldap
     * @param array $userData
     * @return IIdentity
     * @throws PossibleConfigurationErrorException
     */
    public function createIdentity(Manager $ldap, array $userData)
    {
        $roles = array();
        if($this->config['loadGroups'] && !isset($userData['memberOf'])) {
            throw new PossibleConfigurationErrorException('LDAP did not load any memberships (even empty ones) for this user. Make sure you return groups into "memberOf" key of userdata.');
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

    /**
     * @param array $userData
     * @return array
     */
    protected function loadRoleMailsFromGroups(array $userData)
    {
        $roles = array();

        foreach($userData['memberOf'] as $group) {
            if(empty($group['mail'])) {
                continue;
            }

            $roles[] = $group['mail'];
        }

        return $roles;
    }

    /**
     * @param array $userData
     * @return array
     */
    protected function loadRoleMapping(array $userData)
    {
        $roles = array();

        foreach($userData['memberOf'] as $groupDn => $group) {
            if(isset($this->config['rolesMap'][$groupDn])) {
                $roles[] = $this->config['rolesMap'][$groupDn];
            }

            $name = $group['name'];
            if(isset($this->config['rolesMap'][$name])) {
                $roles[] = $this->config['rolesMap'][$name];
            }

            $mail = $group['mail'];
            if(isset($this->config['rolesMap'][$mail])) {
                $roles[] = $this->config['rolesMap'][$mail];
            }
        }

        return $roles;
    }

    /**
     * @param array $userData
     * @return bool
     */
    protected function loadIsAdminMember(array $userData)
    {
        $flatten = Arrays::flatten($userData['memberOf']);
        $isAdmin = false;

        foreach($this->config['adminGroups'] as $one) {
            $isAdmin = $isAdmin || in_array($one, $flatten);
        }

        return $isAdmin;
    }
}
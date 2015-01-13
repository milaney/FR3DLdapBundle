<?php

namespace FR3D\LdapBundle\Ldap;

use FOS\UserBundle\Model\UserManagerInterface;
use FR3D\LdapBundle\Driver\LdapDriverInterface;
use FR3D\LdapBundle\Model\LdapUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;

class LdapManager implements LdapManagerInterface
{
    protected $driver;
    protected $userManager;
    protected $params = array();
    protected $ldapAttributes = array();
    protected $ldapUsernameAttr;

    public function __construct(LdapDriverInterface $driver, UserManagerInterface $userManager, array $params)
    {
        $this->driver = $driver;
        $this->userManager = $userManager;
        $this->params = $params;

        foreach ($this->params['attributes'] as $attr) {
            $this->ldapAttributes[] = $attr['ldap_attr'];
        }

        $this->ldapUsernameAttr = $this->ldapAttributes[0];
    }

    /**
     * {@inheritDoc}
     */
    public function findUserByUsername($username)
    {
        return $this->findUserBy(array($this->ldapUsernameAttr => $username));
    }

    /**
     * {@inheritDoc}
     */
    public function findUserBy(array $criteria)
    {
        $filter  = $this->buildFilter($criteria);
        $entries = $this->driver->search($this->params['baseDn'], $filter, $this->ldapAttributes);
        if ($entries['count'] > 1) {
            throw new \Exception('This search can only return a single user');
        }

        if ($entries['count'] == 0) {
            return false;
        }
        $user = $this->userManager->createUser();
        $this->hydrate($user, $entries[0]);

        return $user;
    }

    /**
     * Build Ldap filter
     *
     * @param  array  $criteria
     * @param  string $condition
     * @return string
     */
    protected function buildFilter(array $criteria, $condition = '&')
    {
        $criteria = self::escapeValue($criteria);
        $filters = array();
        $filters[] = $this->params['filter'];
        foreach ($criteria as $key => $value) {
            $filters[] = sprintf('(%s=%s)', $key, $value);
        }

        return sprintf('(%s%s)', $condition, implode($filters));
    }

    /**
     * Hydrates an user entity with ldap attributes.
     *
     * @param  UserInterface $user  user to hydrate
     * @param  array         $entry ldap result
     *
     * @return UserInterface
     */
    protected function hydrate(UserInterface $user, array $entry)
    {
        $user->setPassword('');

        if ($user instanceof AdvancedUserInterface) {
            $user->setEnabled(true);
        }

        foreach ($this->params['attributes'] as $attr) {
            if (!array_key_exists($attr['ldap_attr'], $entry)) {
                continue;
            }

            $ldapValue = $entry[$attr['ldap_attr']];
            $value = $ldapValue;

            if (array_key_exists('count', $ldapValue)) {
                $value = array_slice($ldapValue, 1);
            }
            if (count($value) == 1) {
                $value = $value[0];
            }

            call_user_func(array($user, $attr['user_method']), $value);
        }

        if (count($this->params['role'])) {
            $this->addRoles($user, $entry);
        }

        if (count($this->params['manages'])) {
            $this->addManages($user, $entry);
        }

        if ($user instanceof LdapUserInterface) {
            $user->setDn($entry['dn']);
        }
    }

    /**
     * Add roles based on role configuration
     *
     * @param UserInterface
     * @param array $entry
     * @return void
     */
    private function addRoles($user, $entry)
    {
        $filter = isset($this->params['role']['filter']) ? $this->params['role']['filter'] : '';

        $entries = $this->driver->search(
            $this->params['role']['baseDn'],
            sprintf('(&%s(%s=%s))', $filter, $this->params['role']['userDnAttribute'], $entry['dn']),
            array($this->params['role']['nameAttribute'])
        );

        for ($i = 0; $i < $entries['count']; $i++) {
            $user->addRole(sprintf('ROLE_%s',
                self::slugify($entries[$i][$this->params['role']['nameAttribute']][0])
            ));
        }
    }

    /**
     * Add users this user manages based on configuration
     *
     * @param UserInterface
     * @param array $entry
     * @return void
     */
    private function addManages($user, $entry)
    {
        $filter = isset($this->params['manages']['filter']) ? $this->params['manages']['filter'] : '';

        $entries = $this->driver->search(
            $this->params['manages']['baseDn'],
            sprintf('(&%s(%s=%s))', $filter, $this->params['manages']['userDnAttribute'], 'CN=Mike McGrail,ou=Medicore,ou=Utrecht-Kanaalweg,dc=efocus,dc=local'/*$entry['dn']*/),
            array($this->params['manages']['nameAttribute'])
        );

        $manages = array();
        for ($i = 0; $i < $entries['count']; $i++) {
            $manages[] = $entries[$i][$this->params['manages']['nameAttribute']][0];
        }
        $user->setManages($manages);
    }

    private static function slugify($role)
    {
        $role = preg_replace('/\W+/', '_', $role);
        $role = trim($role, '_');
        $role = strtoupper($role);

        return $role;
    }

    /**
     * {@inheritDoc}
     */
    public function bind(UserInterface $user, $password)
    {
        return $this->driver->bind($user, $password);
    }

    /**
     * Get a list of roles for the username.
     *
     * @param string $username
     * @return array
     */
    public function getRolesForUsername($username)
    {

    }

    /**
     * Escapes the given VALUES according to RFC 2254 so that they can be safely used in LDAP filters.
     *
     * Any control characters with an ASCII code < 32 as well as the characters with special meaning in
     * LDAP filters "*", "(", ")", and "\" (the backslash) are converted into the representation of a
     * backslash followed by two hex digits representing the hexadecimal value of the character.
     * @see Net_LDAP2_Util::escape_filter_value() from Benedikt Hallinger <beni@php.net>
     * @link http://pear.php.net/package/Net_LDAP2
     * @author Benedikt Hallinger <beni@php.net>
     *
     * @param  string|array $values Array of values to escape
     * @return array Array $values, but escaped
     */
    public static function escapeValue($values = array())
    {
        if (!is_array($values))
            $values = array($values);
        foreach ($values as $key => $val) {
            // Escaping of filter meta characters
            $val = str_replace(array('\\', '*', '(', ')'), array('\5c', '\2a', '\28', '\29'), $val);
            // ASCII < 32 escaping
            $val = Converter::ascToHex32($val);
            if (null === $val) {
                $val          = '\0';  // apply escaped "null" if string is empty
            }
            $values[$key] = $val;
        }

        return (count($values) == 1 && array_key_exists(0, $values)) ? $values[0] : $values;
    }

    /**
     * Undoes the conversion done by {@link escapeValue()}.
     *
     * Converts any sequences of a backslash followed by two hex digits into the corresponding character.
     * @see Net_LDAP2_Util::escape_filter_value() from Benedikt Hallinger <beni@php.net>
     * @link http://pear.php.net/package/Net_LDAP2
     * @author Benedikt Hallinger <beni@php.net>
     *
     * @param  string|array $values Array of values to escape
     * @return array Array $values, but unescaped
     */
    public static function unescapeValue($values = array())
    {
        if (!is_array($values))
            $values = array($values);
        foreach ($values as $key => $value) {
            // Translate hex code into ascii
            $values[$key] = Converter::hex32ToAsc($value);
        }

        return (count($values) == 1 && array_key_exists(0, $values)) ? $values[0] : $values;
    }
}

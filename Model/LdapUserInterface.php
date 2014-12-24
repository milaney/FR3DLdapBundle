<?php

namespace FR3D\LdapBundle\Model;
use Symfony\Component\Security\Core\User\UserInterface;

interface LdapUserInterface
{
    /**
     * Set Ldap Distinguished Name
     *
     * @param string $dn Distinguished Name
     */
    public function setDn($dn);

    /**
     * Get Ldap Distinguished Name
     *
     * @return string Distinguished Name
     */
    public function getDn();

    /**
     * Updates a user.
     *
     * @param UserInterface $user
     *
     * @return void
     */
    //public function updateUser(UserInterface $user);
}

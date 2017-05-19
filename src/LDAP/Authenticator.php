<?php
namespace SeanKndy\Auth\LDAP;

use SeanKndy\Auth\Exceptions\AuthErrorException;
use SeanKndy\Auth\Exceptions\AuthFailedException;

class Authenticator extends \SeanKndy\Auth\Authenticator
{
    private $ldaph;
    private $hosts;
    private $baseDn;
    private $bindRdn;
    private $userFilter, $attribFilter;
    private $attribs;
    
    public function __construct($user, $pass, $hosts)
    {
        parent::__construct($user, $pass);
        
        if (!is_array($hosts))
            $hosts = [$hosts];
        $this->hosts = $hosts;
        $this->userFilter = $this->attribFilter = null;
        $this->bindRdn = $this->baseDn = null;
        $this->attribs = [];
        
        return $this;
    }
    
    //
    // use this if the DN of users is consistent and within the same OU -- for example, if you want to auth only users within
    // ou=Employees,dc=vcn,dc=com, then you can use this method with baseDn = ou=Employees,dc=vcn,dc=com and
    // bindRdn = uid=%u,ou=Employeees,dc=vcn,dc=com
    //
    public static function initBindOnly($user, $pass, $hosts, $baseDn, $bindRdn, $filter = '')
    {
        $obj = (new Authenticator($user, $pass, $hosts))
                ->setBaseDn($baseDn)
                ->setBindRdn($bindRdn)
                ->setAttribFilter($filter);
        return $obj;
    }
    
    //
    // use this if you want to allow authentication to any uid under various OUs.  this will first do a search for the DN, then
    // attempt to bind to that DN afterwards.
    //
    public static function initSearchBind($user, $pass, $hosts, $baseDn, $userFilter, $attribFilter = '')
    {
        $obj = (new Authenticator($user, $pass, $hosts))
                ->setBaseDn($baseDn)
                ->setUserFilter($userFilter)
                ->setAttribFilter($attribFilter);
        return $obj;
    }
    
    public function setBaseDn($dn)
    {
        $this->baseDn = $dn;
        return $this;
    }
    
    public function setBindRdn($dn)
    {
        $this->bindRdn = $dn;
        return $this;
    }
    
    public function setAttribFilter($filter)
    {
        $this->attribFilter = $filter;
        return $this;
    }
    
    public function setUserFilter($filter)
    {
        $this->userFilter = $filter;
        return $this;
    }
    
    public function authenticate(callable $cb = null)
    {
        $this->ldaph = null;
        foreach ($this->hosts as $host)
        {
            if ($this->ldaph = @\ldap_connect($host))
            {
                // verify ldap server is contactable
                if (!($fsock = @\fsockopen($host, 389, $errno, $errstr, 5)))
                    $this->ldaph = null;
                else
                {
                    fclose($fsock);
                    break;
                }
            }
        }
        if (!$this->ldaph)
            throw new AuthErrorException("Failed to connect to LDAP backend server.");
        
        ldap_set_option($this->ldaph, LDAP_OPT_PROTOCOL_VERSION, 3);
        
        // if bindRdn set, then try binding directly to that
        $bindRdn = '';
        if ($this->bindRdn)
        {
            $bindRdn = str_replace('%u', $this->user, $this->bindRdn);
            if (!@\ldap_bind($this->ldaph, $bindRdn, $this->pass))
                throw new AuthFailedException("Failed to bind to LDAP.");
        }
        else
        {
            // search for user first, then try binding to that DN
            $filter = str_replace('%u', $this->user, $this->userFilter);
            $sr = @\ldap_search($this->ldaph, $this->baseDn, $filter, ['dn']);
            if (($entries = \ldap_get_entries($this->ldaph, $sr)) && $entries['count'] == 1)
            {
                $bindRdn = $entries[0]['dn'];
                if (!@\ldap_bind($this->ldaph, $bindRdn, $this->pass))
                    throw new AuthFailedException("Found user, but failed to bind to LDAP.");
            }
            else
                throw new AuthFailedException("Failed to find user in LDAP.");
        }
        
        if ($this->attribFilter)
        {
            $filter = str_replace('%u', $this->user, $this->attribFilter);
            $sr = @\ldap_search($this->ldaph, $bindRdn, $filter);
            if (($entries = \ldap_get_entries($this->ldaph, $sr)) && isset($entries[0]))
            {
                $this->attribs = [];
                for ($i = 0; $i < $entries[0]['count']; $i++)
                {
                    $this->attribs[$entries[0][$i]] = $entries[0][$entries[0][$i]];
                    unset($this->attribs[$entries[0][$i]]['count']);
                }
            }
        }
        
        if ($cb)
            return $cb($this);
        
        return true;
    }
    
    public function postAuthAttributes()
    {
        return $this->attribs;
    }
}


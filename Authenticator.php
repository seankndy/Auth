<?php
namespace SeanKndy\Auth;

abstract class Authenticator
{
    protected $user, $pass;
    
    public function __construct($user, $pass)
    {
        $this->setUser($user);
        $this->setPass($pass);
    }
    
    public function getUser()
    {
        return $this->user;
    }
    
    public function setUser($user)
    {
        $this->user = $user;
    }
    
    public function getPass()
    {
        return $this->pass;
    }
    
    public function setPass($pass)
    {
        $this->pass = $pass;
    }
    
    //
    // authenticate user, throw AuthErrorException or
    // AuthFailedException
    // implementor must call $cb($this) upon successful auth
    //
    abstract public function authenticate(callable $cb = null);
    
    //
    // return any post-authentication attributes that the
    // caller may be interested in receiving (such as a user's
    // real name or email)
    //
    abstract public function postAuthAttributes();
}


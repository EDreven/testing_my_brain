<?php
include_once __DIR__ . '\AuthException.php';
include_once __DIR__ . '\Validate.php';
include_once __DIR__ . '\User.php';
include_once __DIR__ . '\Session.php';
include_once __DIR__ . '\Request.php';  
include_once __DIR__ . '\Attempt.php';

class Auth
{
	private $dbh;
	public $config;
	private $sessionData;
	private $userData;
	private $request;
        private $attempt;
	
	function __construct(\PDO $dbh, $config, $user = null, $session = null, $request = null, $attempt = null)
	{
            $this->dbh = $dbh;
            $this->config = $config;
            if (version_compare(phpversion(), '5.5.0', '<')) {
                require("files/password.php");
            }

            $this->userData = ($user === null ? new User($dbh, $config) : $user);
            $this->sessionData = ($session === null ? new Session($dbh, $config, $this->userData) : $session);
            $this->request = ($request === null ? new Request($dbh, $config) : $request);
            $this->attempt = ($attempt === null ? new Attempt($dbh, $config) : $attempt);
	}
	
	public function login($username, $password, $remember = 0)
	{
            try {
                
                if($this->isBlocked()) {
                    throw new AuthException(AuthException::ERROR_USER_BLOCKED);
                }
                
                try {
                    Validate::validateUsername($username);
                    Validate::validateUsernameBanned($username);
                    Validate::validatePassword($password);
                } catch (AuthException $ex) {
                    throw new AuthException(AuthException::ERROR_AUTH_USERNAME_PASSWORD_INVALID, 1);
                }

                $this->checkRemember($remember);
                $uid = $this->userData->getUID(strtolower($username));

                if (!$uid) {
                    throw new AuthException(AuthException::ERROR_AUTH_USERNAME_PASSWORD_INCORRECT, 1);
                }

                $user = $this->userData->getUser($uid);

                if (!password_verify($password, $user['password'])) {
                    throw new AuthException(AuthException::ERROR_AUTH_USERNAME_PASSWORD_INCORRECT, 1);
                } elseif ($user['isactive'] != 1) {
                    throw new AuthException(AuthException::ERROR_AUTH_ACCOUNT_INACTIVE, 1);
                }

                $sessiondata = $this->sessionData->addSession($user['uid'], $remember);
                if ($sessiondata == false) {
                    throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
                }

                $return = array(
                    'error' => 0,
                    'message' => 'logged_in',
                    'hash' => $sessiondata['hash'],
                    'expire' => $sessiondata['expire'],
                );
                
            } catch (AuthException $ex) {

                if ($ex->getMessage() !== AuthException::ERROR_AUTH_SYSTEM_ERROR &&
                    $ex->getMessage() !== AuthException::ERROR_USER_BLOCKED) {
                    $this->attempt->addAttempt();
                }

                $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
            }

            return $return;
        }
		
	public function logout($hash)
        {
            return (strlen($hash) == 40 ? $this->sessionData->deleteSession($hash) : false);
        }
        
	public function register($email, $username, $password, $repeatpassword)
	{
            try{
		if($this->isBlocked()) {
                    throw new AuthException(AuthException::ERROR_USER_BLOCKED);
                }
                
                Validate::validatePassword($password);
                Validate::validateEmail($email);
                
                if($password !== $repeatpassword) {
                    throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NOMATCH, 1);
		}
		
		$this->isEmailTaken($email);
		if($this->userData->getUID($username)) {
                    throw new AuthException(AuthException::ERROR_VALIDATE_USERNAME_TAKEN, 1);
                }
		
		$this->userData->addUser($email, $username, $password);
		
                $return = array('error' => 0, 'message' => 'register_success');
                
            } catch (AuthException $ex){
                
                if($ex->getMessage() == AuthException::ERROR_VALIDATE_EMAIL_TAKEN || 
                   $ex->getMessage() == AuthException::ERROR_VALIDATE_USERNAME_TAKEN){
                   $this->attempt->addAttempt();
                }
                
                $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
            }
	
            return $return;
	}
	
	public function activate($key)
	{
            try {
                $this->userData->activate($key);
                $return = array('error' => 0, 'message' => 'account_activated');
                
            } catch (AuthException $ex) {

                if ($ex->getMessage() === AuthException::ERROR_AUTH_SYSTEM_ERROR ||
                    $ex->getMessage() === AuthException::ERROR_VALIDATE_KEY_INVALID) {
                    $this->attempt->addAttempt();
                }

                $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
            }

        return $return;
    }
        	
	public function resendActivation($email)
	{
            try{
		if($this->isBlocked()) {
                    throw new AuthException(AuthException::ERROR_USER_BLOCKED);
                }
		Validate::validateEmail($email);
                
		$query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE email = ?");
		$query->execute(array($email));
		if($query->rowCount() == 0) {
                    throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_INCORRECT,1);
		}
		
		$row = $query->fetch(PDO::FETCH_ASSOC);
		if ($this->userData->getUser($row['id'])['isactive'] == 1) {
                    throw new AuthException(AuthException::ERROR_VALIDATE_ALREADY_ACTIVATED,1);
                }
		
		$this->request->addRequest($row['id'], $email, "activation");
                
                $return = array('error' => 0, 'message' => 'activation_sent');
                
            } catch (AuthException $ex){
            
                $this->attempt->addAttempt();
                $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
            }
            
            return $return;
	}
        
	public function validateUsername($username)
        {
            try{
                Validate::validateUsername($username);
                Validate::validateUsernameBanned($username);
            } catch (AuthException $ex){
                $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
            }
            
            return array('error' => 0);
	}
      
	private function isEmailTaken($email)
	{
            $query = $this->dbh->prepare("SELECT * FROM {$this->config->table_users} WHERE email = ?");
            $query->execute(array($email));
            if ($query->rowCount() > 0) {
                throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_TAKEN, 1);
            }
	}
        
        private function checkRemember($remember)
        {
            if ($remember != 0 && $remember != 1) {
                throw new AuthException(AuthException::ERROR_AUTH_REMEMBER_ME_INVALID, 1);
            }
        }

        public function getSessionUID($hash)
	{
            return $this->sessionData->getSessionUID($hash);
	}

	public function checkSession($hash)
	{
            return $this->sessionData->checkSession($hash);
	}

	public function getUser($uid)
	{
            return $this->userData->getUser($uid);
	}

	public function deleteUser($uid, $password) 
	{
            return $this->userData->deleteUser($uid, $password);
	}

	public function getUID($username)
	{
            return $this->userData->getUID($username);
	}

	public function requestReset($email)
	{
            return $this->request->requestReset($email);
	}  
                
	public function getRandomKey($length = 20)
	{
            return $this->request->getRandomKey($length);
	}
        
	protected function isBlocked()
	{
            return $this->attempt->isBlocked();
	}       
        
	public function getHash($string, $salt)
	{
            return $this->userData->getHash($string, $salt);
	}
        	
	public function getEmail($uid)
	{
            return $this->userData->getEmail($uid);
	}
	
	public function sessionUID($hash)
	{
            return $this->sessionData->sessionUID($hash);
	}
        
	public function resetPass($key, $password, $repeatpassword)
	{
            return $this->userData->resetPass($key, $password, $repeatpassword);
	}
        
        public function changePassword($uid, $currpass, $newpass, $repeatnewpass)
	{
            return $this->userData->changePassword($uid, $currpass, $newpass, $repeatnewpass);
	}

	public function changeEmail($uid, $email, $password)
	{
            return $this->userData->changeEmail($uid, $email, $password);
	}
}

?>
<?php

class User
{
    private $dbh;
    private $config;
    public $request;

    private function __construct(\PDO $dbh, $config, $request = null) {
        $this->dbh = $dbh;
        $this->config = $config;
        if(!class_exists('AuthException')) include __DIR__ . 'AuthException.php';
        if(!class_exists('Validate')) include __DIR__ . 'Validate.php';
        
        if($request == null){
            if(!class_exists('Request')) include __DIR__ . 'Request.php';
            $this->request = new Request($dbh, $config);
        }else{
            $this->request = $request;
        }
    }

    public function getUID($username)
    {
        $query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE username = ?");
        $query->execute(array($username));

        return ($query->rowCount() != 0 ? $query->fetch(PDO::FETCH_ASSOC)['id'] : false);
    }
        
    public function addUser($email, $username, $password)
    {
        $query = $this->dbh->prepare("INSERT INTO {$this->config->table_users} VALUES ()");
        if (!$query->execute()) {
            throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
        }

        $uid = $this->dbh->lastInsertId();
        $email = htmlentities($email);

        try {
            $this->request->addRequest($uid, $email, "activation");
        } catch (AuthException $ex) {
            $query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");
            $query->execute(array($uid));
            throw new AuthException($ex->getMessage(), $ex->getCode());
        }

        $salt = substr(strtr(base64_encode(mcrypt_create_iv(22, MCRYPT_DEV_URANDOM)), '+', '.'), 0, 22);
        $username = htmlentities(strtolower($username));
        $password = $this->getHash($password, $salt);
        
        $query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET username = ?, password = ?, email = ?, salt = ? WHERE id = ?");

        if (!$query->execute(array($username, $password, $email, $salt, $uid))) {
            $query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");
            $query->execute(array($uid));
            throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
        }
    }

    public function getUser($uid) 
    {
        return $this->request->getUser($uid);
    }
    	
    public function getEmail($uid)
    {
        $query = $this->dbh->prepare("SELECT email FROM {$this->config->table_users} WHERE id = ?");
        $query->execute(array($uid));
        $row = $query->fetch(PDO::FETCH_ASSOC);

        return $row ? $row['email'] : false;
    }

    public function deleteUser($uid, $password)
    {
        try {
            $this->request->isBlocked();
            Validate::validatePassword($password);

            $getUser = $this->getUser($uid);
            if (!password_verify($password, $getUser['password'])) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT, 1);
            }

            $query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");

            if (!$query->execute(array($uid))) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $query = $this->dbh->prepare("DELETE FROM {$this->config->table_sessions} WHERE uid = ?");

            if (!$query->execute(array($uid))) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $query = $this->dbh->prepare("DELETE FROM {$this->config->table_requests} WHERE uid = ?");

            if (!$query->execute(array($uid))) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $return = array('error' => 0, 'message' => 'account_deleted' );
            
        } catch (AuthException $ex){
            
            if ($ex->getMessage() !== AuthException::ERROR_USER_BLOCKED ||
                $ex->getMessage() !== AuthException::ERROR_AUTH_SYSTEM_ERROR) {

                $this->addAttempt();
            }
                
            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        }
        
        return $return;
    }
    
    public function getHash($string, $salt)
    {
        return password_hash($string, PASSWORD_BCRYPT, ['salt' => $salt, 'cost' => $this->config->bcrypt_cost]);
    }
    
    public function resetPass($key, $password, $repeatpassword)
    {
        try {
            $this->isBlocked();
            Validate::validateKey($key);
            Validate::validatePassword($password);

            if($password !== $repeatpassword) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH, 1);  
            }

            $data = $this->request->getRequest($key, "reset");
            if($data['error'] == 1) {
                throw new AuthException($data['message'], 1);
            }

            $user = $this->getUser($data['uid']);

            if(!$user || password_verify($password, $user['password'])) {
                $this->request->addAttempt();
                $this->request->deleteRequest($data['id']);
                
                if(!$user){
                    throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
                }else{
                    throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH, 1);    
                }
            }

            $password = $this->getHash($password, $user['salt']);
            $query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET password = ? WHERE id = ?");
            $query->execute(array($password, $data['uid']));
            if ($query->rowCount() == 0) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $this->request->deleteRequest($data['id']);
            $return = array('error' => 0, 'message' => 'password_reset');

        } catch (AuthException $ex){

            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        }

        return $return;
    }
    	
    public function changePassword($uid, $currpass, $newpass, $repeatnewpass)
    {
        try{
            $this->request->isBlocked();

            try {
                Validate::validatePassword($currpass);
            } catch (AuthException $ex) {
                $this->request->addAttempt();
                throw new AuthException($ex->getMessage(), $ex->getCode());
            }

            Validate::validatePassword($newpass);

            if($newpass !== $repeatnewpass) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_NOMATCH, 1);
            }

            $user = $this->getUser($uid);
            if(!$user) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $newpass = $this->getHash($newpass, $user['salt']);
            if($currpass == $newpass) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH, 1);
            }

            if(!password_verify($currpass, $user['password'])) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT, 1);
            }

            $query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET password = ? WHERE id = ?");
            $query->execute(array($newpass, $uid));

            $return = array('error' => 0, 'message' => 'password_changed');

        } catch (AuthException $ex){

            if ($ex->getMessage() == AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT ||
                $ex->getMessage() == AuthException::ERROR_AUTH_SYSTEM_ERROR) {

                $this->request->addAttempt();
            }

            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        }

        return $return;
    }

    public function changeEmail($uid, $email, $password)
    {
        try{
            $this->request->isBlocked();
            Validate::validateEmail($email);

            try{
                Validate::validatePassword($password);
            } catch (AuthException $ex) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_NOTVALID, 1);
            }

            $user = $this->getUser($uid);
            if(!$user) {
                $this->request->addAttempt();
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            if(!password_verify($password, $user['password'])) {
                throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT, 1);
            }

            if ($email == $user['email']) {
                throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_NEWEMAIL_MATCH, 1);
            }

            $query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET email = ? WHERE id = ?");
            $query->execute(array($email, $uid));
            if ($query->rowCount() == 0) {
                throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
            }

            $return = array('error' => 0, 'message' => 'email_changed' );

        } catch (AuthException $ex){

            if ($ex->getMessage() !== AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT &&
                $ex->getMessage() !== AuthException::ERROR_VALIDATE_EMAIL_NEWEMAIL_MATCH) {

                $this->request->addAttempt();
            }

            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        } 

        return $return;
    }
}
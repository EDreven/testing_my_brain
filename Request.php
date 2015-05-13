<?php

class Request {

    private $dbh;
    private $config;
        
    private function __construct(\PDO $dbh, $config)
    {
        $this->dbh = $dbh;
        $this->config = $config;
        
        if(!class_exists('AuthException')) include __DIR__ . 'AuthException.php';
        if(!class_exists('Validate')) include __DIR__ . 'Validate.php';
    }
    
    public function getRequest($key, $type) 
    {
        try{
            $query = $this->dbh->prepare("SELECT id, uid, expire FROM {$this->config->table_requests} WHERE rkey = ? AND type = ?");
            $query->execute(array($key, $type));
            if ($query->rowCount() === 0) {
                throw new AuthException(AuthException::ERROR_VALIDATE_KEY_INCORRECT, 1);
            }
            
            $row = $query->fetch();
            if (strtotime(date("Y-m-d H:i:s")) > strtotime($row['expire'])) {
                $this->deleteRequest($row['id']);
                throw new AuthException(AuthException::ERROR_VALIDATE_KEY_EXPIRED, 1);
            }

            $return = array('error' => 0, 'id' => $row['id'], 'uid' => $row['uid']);
        } catch (AuthException $ex){
            
            $this->addAttempt();
            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        }
        
        return $return;
    }
    
    public function requestReset($email)
    {
        try {
            $this->userData->isBlocked();

            try {
                Validate::validateEmail($email);
            } catch (AuthException $ex) {
                throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_INVALID, 1);
            }

            $query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE email = ?");
            $query->execute(array($email));
            if ($query->rowCount() == 0) {
                throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_INCORRECT, 1);
            }

            $addRequest = $this->addRequest($query->fetch(PDO::FETCH_ASSOC)['id'], $email, "reset");
            if ($addRequest['error'] == 1) {
                throw new AuthException($addRequest['message'], 1);
            }

            $return = array('error' => 0, 'message' => 'reset_requested');
        } catch (AuthException $ex) {

            if ($ex->getMessage() != AuthException::ERROR_VALIDATE_EMAIL_INVALID) {
                $this->addAttempt();
            }

            $return = array('error' => $ex->getCode(), 'message' => $ex->getMessage());
        }

        return $return;
    }

    public function addRequest($uid, $email, $type)
    {
        if ($type != "activation" && $type != "reset") {
            throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
        }
        
        $query = $this->dbh->prepare("SELECT id, expire FROM {$this->config->table_requests} WHERE uid = ? AND type = ?");
        $query->execute(array($uid, $type));
        if ($query->rowCount() > 0) {
            $row = $query->fetch(PDO::FETCH_ASSOC);
            if (strtotime(date("Y-m-d H:i:s")) < strtotime($row['expire'])) {
                throw new AuthException(AuthException::ERROR_REQUEST_EXISTS, 1);
            }

            $this->deleteRequest($row['id']);
        }
        
        if ($type == "activation" && $this->getUser($uid)['isactive'] == 1) {
            throw new AuthException(AuthException::ERROR_VALIDATE_ALREADY_ACTIVATED, 1);
        }
        
        $key = $this->getRandomKey(20);
        $expire = date("Y-m-d H:i:s", strtotime("+1 day"));
        $query = $this->dbh->prepare("INSERT INTO {$this->config->table_requests} (uid, rkey, expire, type) VALUES (?, ?, ?, ?)");
        if (!$query->execute(array($uid, $key, $expire, $type))) {
            throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
        }
        
        if ($type == "activation") {
            $message = "Account activation required : <strong><a href=\"{$this->config->site_url}/activate/{$key}\">Activate my account</a></strong>";
            $subject = "{$this->config->site_name} - Account Activation";
        } else {
            $message = "Password reset request : <strong><a href=\"{$this->config->site_url}/reset/{$key}\">Reset my password</a></strong>";
            $subject = "{$this->config->site_name} - Password reset request";
        }

        $headers = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
        $headers .= "From: {$this->config->site_email}" . "\r\n";
        
        if (!mail($email, $subject, $message, $headers)) {
            throw new AuthException(AuthException::ERROR_AUTH_SYSTEM_ERROR, 1);
        }
    }

    private function deleteRequest($id)
    {
        $query = $this->dbh->prepare("DELETE FROM {$this->config->table_requests} WHERE id = ?");
        return $query->execute(array($id));
    }
    
    public function addAttempt()
    {
        $ip = $this->getIp();
        $query = $this->dbh->prepare("SELECT count FROM {$this->config->table_attempts} WHERE ip = ?");
        $query->execute(array($ip));
        $row = $query->fetch(PDO::FETCH_ASSOC);

        $attempt_expiredate = date("Y-m-d H:i:s", strtotime("+30 minutes"));

        if (!$row) {
            $attempt_count = 1;
            $query = $this->dbh->prepare("INSERT INTO {$this->config->table_attempts} (count, expiredate, ip) VALUES (?, ?, ?)");
        }else{
            $attempt_count = $row['count'] + 1;
            $query = $this->dbh->prepare("UPDATE {$this->config->table_attempts} SET count=?, expiredate=? WHERE ip=?");
        }
        
        return $query->execute(array($attempt_count, $attempt_expiredate, $ip));
    }

    private function deleteAttempts($ip)
    {
        $query = $this->dbh->prepare("DELETE FROM {$this->config->table_attempts} WHERE ip = ?");
        return $query->execute(array($ip));
    }
    
    
    public function getUser($uid) 
    {
        $query = $this->dbh->prepare("SELECT id AS uid, username, password, email, salt, isactive FROM {$this->config->table_users} WHERE id = ?");
        $query->execute(array($uid));

        if ($query->rowCount() == 0) {
            $data = $query->fetch(PDO::FETCH_ASSOC);
        }
                
        return (isset($data) && $data ? $data : false);   // где-то может присутствовать явная проверка (getUser($uid) === false), а метод изначально public
    }
    
        
    public function isBlocked() 
    {
        $ip = $this->getIp();
        $query = $this->dbh->prepare("SELECT count, expiredate FROM {$this->config->table_attempts} WHERE ip = ?");
        $query->execute(array($ip));

        if ($query->rowCount() !== 0) {

            $row = $query->fetch(PDO::FETCH_ASSOC);
            $expiredate = strtotime($row['expiredate']);
            $currentdate = strtotime(date("Y-m-d H:i:s"));

            if ($row['count'] == 5) {
                if ($currentdate < $expiredate) {
                    throw new AuthException(AuthException::ERROR_USER_BLOCKED);
                }
                $this->deleteAttempts($ip);
                
            } elseif ($currentdate > $expiredate) {
                $this->deleteAttempts($ip);
            }
        }

        return false;
    }
                    
    public function getRandomKey($length = 20)
    {
            $chars = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
            $key = "";
            for ($i = 0; $i < $length; $i++) {
                    $key .= $chars{mt_rand(0, strlen($chars) - 1)};
            }
            return $key;
    }
        
    private function getIp()
    {
        return $_SERVER['REMOTE_ADDR'];
    }
}
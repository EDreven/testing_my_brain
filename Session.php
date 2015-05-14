<?php
include_once __DIR__ . 'Request.php';
include_once __DIR__ . 'Attempt.php';

class Session
{
    private $dbh;
    private $config;
    private $request;
    private $attempt;
        
    private function __construct(\PDO $dbh, $config, $request = null, $attempt = null)
    {
        $this->dbh = $dbh;
        $this->config = $config;
        $this->request = ($request == null ? new Request($dbh, $config) : $request);
        $this->attempt = ($attempt == null ? new Attempt($dbh, $config) : $attempt);
    }
        
    public function addSession($uid, $remember)
    {
        $ip = $this->attempt->getIp();
        $user = $this->request->getUser($uid);

        if(!$user) {
            return false;
        }
        
        $data['hash'] = sha1($user['salt'] . microtime());
        $agent = $_SERVER['HTTP_USER_AGENT'];
        $this->deleteExistingSessions($uid);
        
        if($remember == true) {
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->config->cookie_remember));
            $data['expiretime'] = strtotime($data['expire']);
        } else {
            $data['expire'] = date("Y-m-d H:i:s", strtotime($this->config->cookie_remember));
            $data['expiretime'] = 0;
        }
        
        $data['cookie_crc'] = sha1($data['hash'] . $this->config->site_key);
        $query = $this->dbh->prepare("INSERT INTO {$this->config->table_sessions} (uid, hash, expiredate, ip, agent, cookie_crc) VALUES (?, ?, ?, ?, ?, ?)");

        if(!$query->execute(array($uid, $data['hash'], $data['expire'], $ip, $agent, $data['cookie_crc']))) {
                return false;
        }

        $data['expire'] = strtotime($data['expire']);
        return $data;
    }

    private function deleteExistingSessions($uid)
    {
        $query = $this->dbh->prepare("DELETE FROM {$this->config->table_sessions} WHERE uid = ?");
        return $query->execute(array($uid));
    }

    public function deleteSession($hash)
    {
        $query = $this->dbh->prepare("DELETE FROM {$this->config->table_sessions} WHERE hash = ?");
        return $query->execute(array($hash));
    }

    public function getSessionUID($hash)
    {
        $query = $this->dbh->prepare("SELECT uid FROM {$this->config->table_sessions} WHERE hash = ?");
        $query->execute(array($hash));
        if ($query->rowCount() == 0) {
            return false;
        }
        return $query->fetch(PDO::FETCH_ASSOC)['uid'];
    }

    public function checkSession($hash)
    {
        $ip = $this->attempt->getIp();
        if ($this->attempt->isBlocked()) {
            return false;
        }

        if (strlen($hash) != 40) {
                return false;
        }
        $query = $this->dbh->prepare("SELECT id, uid, expiredate, ip, agent, cookie_crc FROM {$this->config->table_sessions} WHERE hash = ?");
        $query->execute(array($hash));
        if ($query->rowCount() == 0) {
            return false;
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);
        $sid = $row['id'];
        $uid = $row['uid'];
        $expiredate = strtotime($row['expiredate']);
        $currentdate = strtotime(date("Y-m-d H:i:s"));
        $db_ip = $row['ip'];
        $db_agent = $row['agent'];
        $db_cookie = $row['cookie_crc'];

        if ($currentdate > $expiredate) {
            $this->deleteExistingSessions($uid);
            return false;
        }

        if ($ip != $db_ip) {
            if ($_SERVER['HTTP_USER_AGENT'] != $db_agent) {
                $this->deleteExistingSessions($uid);
                return false;
            }

            return $this->updateSessionIp($sid, $ip);
        }

        if ($db_cookie == sha1($hash . $this->config->site_key)) {
            return true;
        }

        return false;
    }

    private function updateSessionIp($sid, $ip)
    {
        $query = $this->dbh->prepare("UPDATE {$this->config->table_sessions} SET ip = ? WHERE id = ?");
        return $query->execute(array($ip, $sid));
    }
    
    public function sessionUID($hash)
    {
        if (strlen($hash) == 40) {
            $query = $this->dbh->prepare("SELECT uid FROM {$this->config->table_sessions} WHERE hash = ?");
            $query->execute(array($hash));
            if ($query->rowCount() != 0) {
                $sessionUID = $query->fetch(PDO::FETCH_ASSOC)['uid'];
            }
        }
        return (isset($sessionUID) ? $sessionUID : false);
    }

}
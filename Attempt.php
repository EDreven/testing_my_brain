<?php

class Attempt{

    private $dbh;
    private $config;
        
    private function __construct(\PDO $dbh, $config)
    {
        $this->dbh = $dbh;
        $this->config = $config;
    }
    
    public function isBlocked() 
    {
        $isBlocked = false;
        $ip = $this->getIp();
        $query = $this->dbh->prepare("SELECT count, expiredate FROM {$this->config->table_attempts} WHERE ip = ?");
        $query->execute(array($ip));

        if ($query->rowCount() !== 0) {

            $row = $query->fetch(PDO::FETCH_ASSOC);
            $expiredate = strtotime($row['expiredate']);
            $currentdate = strtotime(date("Y-m-d H:i:s"));
        
            if ($currentdate >= $expiredate) {
                $this->deleteAttempts($ip);
            } elseif ($row['count'] >= 5) {
               $isBlocked = true;
            }
        }

        return $isBlocked;
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
    
    public function getIp()
    {
        return $_SERVER['REMOTE_ADDR'];
    }
}
<?php

class Auth
{
	private $dbh;
	public $config;
	
	private function __construct(\PDO $dbh, $config)
	{
		$this->dbh = $dbh;
		$this->config = $config;
		if (version_compare(phpversion(), '5.5.0', '<')) {
			require("files/password.php");
		}
	}
	
	public function login($username, $password, $remember = 0)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
			
		$validateUsername = $this->validateUsername($username);
		$validatePassword = $this->validatePassword($password);
		if ($validateUsername['error'] == 1) {
			$this->addAttempt();
			
			$return['message'] = "username_password_invalid";
			return $return;
		} elseif($validatePassword['error'] == 1) {
			$this->addAttempt();
			
			$return['message'] = "username_password_invalid";
			return $return;
		} elseif($remember != 0 && $remember != 1) {
			$this->addAttempt();
			
			$return['message'] = "remember_me_invalid";
			return $return;
		}
		
		$uid = $this->getUID(strtolower($username));
		if(!$uid) {
			$this->addAttempt();
			$return['message'] = "username_password_incorrect";
			return $return;
		}
		
		$user = $this->getUser($uid);
		
		if (!password_verify($password, $user['password'])) {
			$this->addAttempt();
			$return['message'] = "username_password_incorrect";
			return $return;
		}
		
		if ($user['isactive'] != 1) {
			$this->addAttempt();
			$return['message'] = "account_inactive";
			return $return;
		}
				
		$sessiondata = $this->addSession($user['uid'], $remember);
		if($sessiondata == false) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$return['error'] = 0;
		$return['message'] = "logged_in";
		$return['hash'] = $sessiondata['hash'];
		$return['expire'] = $sessiondata['expiretime'];
		return $return;
	}
	
	public function register($email, $username, $password, $repeatpassword)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		} 
		
		$validateEmail = $this->validateEmail($email);
		$validateUsername = $this->validateUsername($username);
		$validatePassword = $this->validatePassword($password);
		if ($validateEmail['error'] == 1) {
			$return['message'] = $validateEmail['message'];
			return $return;
		} elseif ($validateUsername['error'] == 1) {
			$return['message'] = $validateUsername['message'];
			return $return;
		} elseif ($validatePassword['error'] == 1) {
			$return['message'] = $validatePassword['message'];
			return $return;
		} elseif($password !== $repeatpassword) {
			$return['message'] = "password_nomatch";
			return $return;
		}
		
		if ($this->isEmailTaken($email)) {
			$this->addAttempt();
			$return['message'] = "email_taken";
			return $return;
		}
		
		if ($this->isUsernameTaken($username)) {
			$this->addAttempt();
			$return['message'] = "username_taken";
			return $return;
		}
		
		$addUser = $this->addUser($email, $username, $password);
		if($addUser['error'] != 0) {
			$return['message'] = $addUser['message'];
			return $return;
		}
		
		$return['error'] = 0;
		$return['message'] = "register_success";
		
		return $return;
	}
	
	public function activate($key)
	{
		$return['error'] = 1;
		if($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
			
		if(strlen($key) !== 20) {
			$this->addAttempt();
			$return['message'] = "key_invalid";
			return $return;
		}
		
		$getRequest = $this->getRequest($key, "activation");
		if($getRequest['error'] == 1) {
			$return['message'] = $getRequest['message'];
			return $return;
		}
		
		if($this->getUser($getRequest['uid'])['isactive'] == 1) {
			$this->addAttempt();
			$this->deleteRequest($getRequest['id']);
			$return['message'] = "system_error";
			return $return;
		}
		$query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET isactive = ? WHERE id = ?");
		$query->execute(array(1, $getRequest['uid']));
		$this->deleteRequest($getRequest['id']);
		$return['error'] = 0;
		$return['message'] = "account_activated";
		
		return $return;
	}
	
	public function requestReset($email)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
		$validateEmail = $this->validateEmail($email);
		if ($validateEmail['error'] == 1) {
			$return['message'] = "email_invalid";
			return $return;
		}
		
		$query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE email = ?");
		$query->execute(array($email));
		if ($query->rowCount() == 0) {
			$this->addAttempt();
			$return['message'] = "email_incorrect";
			return $return;
		}
		if ($this->addRequest($query->fetch(PDO::FETCH_ASSOC)['id'], $email, "reset")['error'] == 1) {
			$this->addAttempt();
			$return['message'] = $addRequest['message'];
			return $return;
		}
		$return['error'] = 0;
		$return['message'] = "reset_requested";
		return $return;
	}
	
	public function logout($hash)
	{
		if (strlen($hash) != 40) {
			return false;
		}
		return $this->deleteSession($hash);
	}
	
	public function getHash($string, $salt)
	{
		return password_hash($string, PASSWORD_BCRYPT, ['salt' => $salt, 'cost' => $this->config->bcrypt_cost]);
	}
	
	public function getUID($username)
	{
		$query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE username = ?");
		$query->execute(array($username));
		if($query->rowCount() == 0) {
			return false;
		}
		
		return $query->fetch(PDO::FETCH_ASSOC)['id'];
	}
	
	private function addSession($uid, $remember)
	{
		$ip = $this->getIp();
		$user = $this->getUser($uid);
		
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
	
	private function deleteSession($hash)
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
		$ip = $this->getIp();
		if ($this->isBlocked()) {
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
	
	private function isEmailTaken($email)
	{
		$query = $this->dbh->prepare("SELECT * FROM {$this->config->table_users} WHERE email = ?");
		$query->execute(array($email));
		if ($query->rowCount() == 0) {
			return false;
		}
		
		return true;
	}
	
	private function isUsernameTaken($username)
	{
		if($this->getUID($username)) {
			return true;
		}
			
		return false;
	}
	
	private function addUser($email, $username, $password)
	{
		$return['error'] = 1;
		$query = $this->dbh->prepare("INSERT INTO {$this->config->table_users} VALUES ()");
		if(!$query->execute()) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$uid = $this->dbh->lastInsertId();
		$email = htmlentities($email);
		$addRequest = $this->addRequest($uid, $email, "activation");
		if($addRequest['error'] == 1) {
			$query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");
			$query->execute(array($uid));
			$return['message'] = $addRequest['message'];
			return $return;
		}
		$salt = substr(strtr(base64_encode(mcrypt_create_iv(22, MCRYPT_DEV_URANDOM)), '+', '.'), 0, 22);
		$username = htmlentities(strtolower($username));
		$password = $this->getHash($password, $salt);
		$query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET username = ?, password = ?, email = ?, salt = ? WHERE id = ?");
		
		if(!$query->execute(array($username, $password, $email, $salt, $uid))) {
			$query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");
			$query->execute(array($uid));
			$return['message'] = "system_error";
			return $return;
		}
		$return['error'] = 0;
		return $return;
	}
	
	public function getUser($uid)
	{
		$query = $this->dbh->prepare("SELECT username, password, email, salt, isactive FROM {$this->config->table_users} WHERE id = ?");
		$query->execute(array($uid));
		if ($query->rowCount() == 0) {
			return false;
		}
		
		$data = $query->fetch(PDO::FETCH_ASSOC);
		if (!$data) {
			return false;
		}
		
		$data['uid'] = $uid;
		return $data;
	}
	
	public function deleteUser($uid, $password) 
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";		
			return $return;
		}
		
		$validatePassword = $this->validatePassword($password);
		
		if($validatePassword['error'] == 1) {
			$this->addAttempt();
			$return['message'] = $validatePassword['message'];
			return $return;
		}
		$getUser = $this->getUser($uid);
		if(!password_verify($password, $getUser['password'])) {
			$this->addAttempt();
			$return['message'] = "password_incorrect";
			return $return;
		}
		
		$query = $this->dbh->prepare("DELETE FROM {$this->config->table_users} WHERE id = ?");
		
		if(!$query->execute(array($uid))) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$query = $this->dbh->prepare("DELETE FROM {$this->config->table_sessions} WHERE uid = ?");
		
		if(!$query->execute(array($uid))) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$query = $this->dbh->prepare("DELETE FROM {$this->config->table_requests} WHERE uid = ?");
		
		if(!$query->execute(array($uid))) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$return['error'] = 0;
		$return['message'] = "account_deleted";
		return $return;
	}
	
	private function addRequest($uid, $email, $type)
	{
		$return['error'] = 1;
		if($type != "activation" && $type != "reset") {
			$return['message'] = "system_error";
			return $return;
		}
		$query = $this->dbh->prepare("SELECT id, expire FROM {$this->config->table_requests} WHERE uid = ? AND type = ?");
		$query->execute(array($uid, $type));
		if($query->rowCount() > 0) {
			$row = $query->fetch(PDO::FETCH_ASSOC);
			$expiredate = strtotime($row['expire']);
			$currentdate = strtotime(date("Y-m-d H:i:s"));
			if ($currentdate < $expiredate) {
				$return['message'] = "request_exists";
				return $return;
			}
			
			$this->deleteRequest($row['id']);
		}
		if($type == "activation" && $this->getUser($uid)['isactive'] == 1) {
			$return['message'] = "already_activated";
			return $return;
		}
		$key = $this->getRandomKey(20);
		$expire = date("Y-m-d H:i:s", strtotime("+1 day"));
		$query = $this->dbh->prepare("INSERT INTO {$this->config->table_requests} (uid, rkey, expire, type) VALUES (?, ?, ?, ?)");
		if(!$query->execute(array($uid, $key, $expire, $type))) {
			$return['message'] = "system_error";
			return $return;
		}
		if($type == "activation") {
			$message = "Account activation required : <strong><a href=\"{$this->config->site_url}/activate/{$key}\">Activate my account</a></strong>";
			$subject = "{$this->config->site_name} - Account Activation";
		} else {
			$message = "Password reset request : <strong><a href=\"{$this->config->site_url}/reset/{$key}\">Reset my password</a></strong>";		
			$subject = "{$this->config->site_name} - Password reset request";
		}
		
		$headers  = 'MIME-Version: 1.0' . "\r\n";
		$headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
		$headers .= "From: {$this->config->site_email}" . "\r\n";
		if(!mail($email, $subject, $message, $headers)) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$return['error'] = 0;
		return $return;
	}
	
	private function getRequest($key, $type)
	{
		$return['error'] = 1;
		$query = $this->dbh->prepare("SELECT id, uid, expire FROM {$this->config->table_requests} WHERE rkey = ? AND type = ?");
		$query->execute(array($key, $type));
		if ($query->rowCount() === 0) {
			$this->addAttempt();
			$return['message'] = "key_incorrect";
			return $return;
		}
		$row = $query->fetch();
		$expiredate = strtotime($row['expire']);
		$currentdate = strtotime(date("Y-m-d H:i:s"));
		if ($currentdate > $expiredate) {
			$this->addAttempt();
			$this->deleteRequest($row['id']);
			$return['message'] = "key_expired";
			return $return;
		}
		
		$return['error'] = 0;
		$return['id'] = $row['id'];
		$return['uid'] = $row['uid'];
		
		return $return;
	}
	
	private function deleteRequest($id)
	{
		$query = $this->dbh->prepare("DELETE FROM {$this->config->table_requests} WHERE id = ?");
		return $query->execute(array($id));
	}
	
	public function validateUsername($username) {
		$return['error'] = 1;
		if (strlen($username) < 3) {
			$return['message'] = "username_short";
			return $return;
		} elseif (strlen($username) > 30) {
			$return['message'] = "username_long";
			return $return;
		} elseif (!ctype_alnum($username)) {
			$return['message'] = "username_invalid";
			return $return;
		}
		
		$bannedUsernames = file(__DIR__ . "/files/banned-usernames.txt", FILE_IGNORE_NEW_LINES);
		
		if(0 < count(array_intersect(array(strtolower($username)), $bannedUsernames))) {
			$return['message'] = "username_banned";
			return $return;
		}
			
		$return['error'] = 0;
		return $return;
	}
	
	private function validatePassword($password) {
		$return['error'] = 1;
		if (strlen($password) < 6) {
			$return['message'] = "password_short";
			return $return;
		} elseif (strlen($password) > 72) {
			$return['message'] = "password_long";
			return $return;
		} elseif (!preg_match('@[A-Z]@', $password) || !preg_match('@[a-z]@', $password) || !preg_match('@[0-9]@', $password)) {
			$return['message'] = "password_invalid";
			return $return;
		}
		
		$return['error'] = 0;
		return $return;
	}
	
	private function validateEmail($email) {
		$return['error'] = 1;
		if (strlen($email) < 5) {
			$return['message'] = "email_short";
			return $return;
		} elseif (strlen($email) > 100) {
			$return['message'] = "email_long";
			return $return;
		} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			$return['message'] = "email_invalid";
			return $return;
		}
		
		$bannedEmails = file(__DIR__ . "/files/banned-emails.txt", FILE_IGNORE_NEW_LINES);
		
		if(0 < count(array_intersect(array(strtolower($email)), $bannedEmails))) {
			$return['message'] = "email_banned";
			return $return;
		}
		
		$return['error'] = 0;
		return $return;
	}
	
	public function resetPass($key, $password, $repeatpassword)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
		if(strlen($key) != 20) {
			$return['message'] = "key_invalid";
			return $return;
		}
		$validatePassword = $this->validatePassword($password);
		if($validatePassword['error'] == 1) {
			$return['message'] = $validatePassword['message'];
			return $return;
		}
		if($password !== $repeatpassword) {
			// Passwords don't match
			$return['message'] = "newpassword_nomatch";
			return $return;
		}
		$data = $this->getRequest($key, "reset");
		if($data['error'] == 1) {
			$return['message'] = $data['message'];
			return $return;
		}
		
		$user = $this->getUser($data['uid']);
		
		if(!$user) {
			$this->addAttempt();
			$this->deleteRequest($data['id']);
			$return['message'] = "system_error";
			return $return;
		}
		
		if(password_verify($password, $user['password'])) {
			$this->addAttempt();
			$this->deleteRequest($data['id']);
			$return['message'] = "newpassword_match";
			return $return;
		}
		
		$password = $this->getHash($password, $user['salt']);
		$query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET password = ? WHERE id = ?");
		$query->execute(array($password, $data['uid']));
		if ($query->rowCount() == 0) {
			$return['message'] = "system_error";
			return $return;
		}
		
		$this->deleteRequest($data['id']);
		$return['error'] = 0;
		$return['message'] = "password_reset";
		
		return $return;
	}
	
	public function resendActivation($email)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
		
		$validateEmail = $this->validateEmail($email);
		if($validateEmail['error'] == 1) {
			$return['message'] = $validateEmail['message'];
			return $return;
		}
		
		$query = $this->dbh->prepare("SELECT id FROM {$this->config->table_users} WHERE email = ?");
		$query->execute(array($email));
		if($query->rowCount() == 0) {
			$this->addAttempt();
			$return['message'] = "email_incorrect";
			return $return;
		}
		
		$row = $query->fetch(PDO::FETCH_ASSOC);
		if ($this->getUser($row['id'])['isactive'] == 1) {
			$this->addAttempt();
			$return['message'] = "already_activated";
			return $return;
		}
		
		$addRequest = $this->addRequest($row['id'], $email, "activation");
		if ($addRequest['error'] == 1) {
			$this->addAttempt();
			$return['message'] = $addRequest['message'];
			return $return;
		}
		$return['error'] = 0;
		$return['message'] = "activation_sent";
		return $return;
	}
	
	public function sessionUID($hash)
	{
		if (strlen($hash) != 40) {
			return false;
		}
		
		$query = $this->dbh->prepare("SELECT uid FROM {$this->config->table_sessions} WHERE hash = ?");
		$query->execute(array($hash));
		
		if($query->rowCount() == 0) {
			return false;
		}
		
		return $query->fetch(PDO::FETCH_ASSOC)['uid'];
	}
	
	public function changePassword($uid, $currpass, $newpass, $repeatnewpass)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
		
		$validatePassword = $this->validatePassword($currpass);
		
		if($validatePassword['error'] == 1) {
			$this->addAttempt();
			$return['message'] = $validatePassword['message'];
			return $return;
		}
		$validatePassword = $this->validatePassword($newpass);
		if($validatePassword['error'] == 1) {
			$return['message'] = $validatePassword['message'];
			return $return;
		} elseif($newpass !== $repeatnewpass) {
			$return['message'] = "newpassword_nomatch";
			return $return;
		}
		$user = $this->getUser($uid);
		
		if(!$user) {
			$this->addAttempt();
			$return['message'] = "system_error";
			return $return;
		}
		$newpass = $this->getHash($newpass, $user['salt']);
		if($currpass == $newpass) {
			$return['message'] = "newpassword_match";
			return $return;
		}
		if(!password_verify($currpass, $user['password'])) {
			$this->addAttempt();
			$return['message'] = "password_incorrect";
			return $return;
		}
		$query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET password = ? WHERE id = ?");
		$query->execute(array($newpass, $uid));
		$return['error'] = 0;
		$return['message'] = "password_changed";
		return $return;
	}
	
	public function getEmail($uid)
	{
		$query = $this->dbh->prepare("SELECT email FROM {$this->config->table_users} WHERE id = ?");
		$query->execute(array($uid));
		$row = $query->fetch(PDO::FETCH_ASSOC);
		if (!$row) {
			return false;
		} 
			
		return $row['email'];
	}
	
	public function changeEmail($uid, $email, $password)
	{
		$return['error'] = 1;
		if ($this->isBlocked()) {
			$return['message'] = "user_blocked";
			return $return;
		}
		
		$validateEmail = $this->validateEmail($email);
		if($validateEmail['error'] == 1)
		{
			$return['message'] = $validateEmail['message'];
			return $return;
		}
		
		$validatePassword = $this->validatePassword($password);
		
		if ($validatePassword['error'] == 1) {
			$return['message'] = "password_notvalid";
			return $return;
		}
		$user = $this->getUser($uid);
		
		if(!$user) {
			$this->addAttempt();
			$return['message'] = "system_error";
			return $return;
		}
		if(!password_verify($password, $user['password'])) {
			$this->addAttempt();
			$return['message'] = "password_incorrect";
			return $return;
		}
		if ($email == $user['email']) {
			$this->addAttempt();
			$return['message'] = "newemail_match";
			return $return;
		}
		
		$query = $this->dbh->prepare("UPDATE {$this->config->table_users} SET email = ? WHERE id = ?");
		$query->execute(array($email, $uid));
		if ($query->rowCount() == 0) {
			$return['message'] = "system_error";
			return $return;
		}
		$return['error'] = 0;
		$return['message'] = "email_changed";
		return $return;
	}
	
	private function isBlocked()
	{
		$ip = $this->getIp();
		$query = $this->dbh->prepare("SELECT count, expiredate FROM {$this->config->table_attempts} WHERE ip = ?");
		$query->execute(array($ip));
		if($query->rowCount() == 0) {
			return false;
		}
		$row = $query->fetch(PDO::FETCH_ASSOC);
		$expiredate = strtotime($row['expiredate']);
		$currentdate = strtotime(date("Y-m-d H:i:s"));
		if ($row['count'] == 5) {
			if ($currentdate < $expiredate) {
				return true;
			}
			$this->deleteAttempts($ip);
			return false;
		}
			
		if ($currentdate > $expiredate) {
			$this->deleteAttempts($ip);
		}
		return false;
	}
	
	private function addAttempt()
	{
		$ip = $this->getIp();
		$query = $this->dbh->prepare("SELECT count FROM {$this->config->table_attempts} WHERE ip = ?");
		$query->execute(array($ip));
		$row = $query->fetch(PDO::FETCH_ASSOC);
		
		$attempt_expiredate = date("Y-m-d H:i:s", strtotime("+30 minutes"));
		
		if (!$row) {
			$attempt_count = 1;
			$query = $this->dbh->prepare("INSERT INTO {$this->config->table_attempts} (ip, count, expiredate) VALUES (?, ?, ?)");
			return $query->execute(array($ip, $attempt_count, $attempt_expiredate));
		}
		
		$attempt_count = $row['count'] + 1;
		$query = $this->dbh->prepare("UPDATE {$this->config->table_attempts} SET count=?, expiredate=? WHERE ip=?");
		return $query->execute(array($attempt_count, $attempt_expiredate, $ip));
	}
	
	private function deleteAttempts($ip)
	{
		$query = $this->dbh->prepare("DELETE FROM {$this->config->table_attempts} WHERE ip = ?");
		return $query->execute(array($ip));
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
?>
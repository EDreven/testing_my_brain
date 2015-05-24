<?php
include_once __DIR__ . '\..\Auth.php';
include_once __DIR__ . '\..\User.php';
include_once __DIR__ . '\..\Session.php';
include_once __DIR__ . '\..\Request.php';  
include_once __DIR__ . '\..\Attempt.php';

class mockUser extends User
{
    public function __construct ()
    {}
}

class mockSession extends Session
{
    public function __construct ()
    {}
}

class mockRequest extends Request
{
    public function __construct ()
    {}
}

class mockAttempt extends Attempt
{
    public function __construct ()
    {}
}


class AuthTest extends PHPUnit_Framework_TestCase
{
    public $request;
    
    public function getLoginDataProvider()
    {
        $validateUserName = 'validateUserName';
        $validatePass = 'Validate-Pass_123';
        
        return array(
            array(true, false, false, false, false, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED)),
            array(false, false, false, false, false, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_USERNAME_PASSWORD_INVALID)),
            array(false, $validateUserName, false, false, false, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_USERNAME_PASSWORD_INVALID)),
            array(false, $validateUserName, $validatePass, 2, false, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_REMEMBER_ME_INVALID)),
            array(false, $validateUserName, $validatePass, 1, false, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_USERNAME_PASSWORD_INCORRECT)),
            array(false, $validateUserName, $validatePass, 1, 1, array('uid' => 1, 'password' => false, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_USERNAME_PASSWORD_INCORRECT)),
            array(false, $validateUserName, $validatePass, 1, 1, array('uid' => 1, 'password' => $validatePass, 'isactive' => false), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_ACCOUNT_INACTIVE)),
            array(false, $validateUserName, $validatePass, 1, 1, array('uid' => 1, 'password' => $validatePass, 'isactive' => 1), false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_SYSTEM_ERROR)),
            array(false, $validateUserName, $validatePass, 1, 1, array('uid' => 1, 'password' => $validatePass, 'isactive' => 1), array('hash' => 1, 'expire' => 1), array('error' => 0,'message' => 'logged_in','hash' => 1,'expire' => 1))
        );
    }
 
    /**
     * @dataProvider getLoginDataProvider
     */
    public function testLogin($isBlocked, $username, $password, $remember, $getUID, $getUser, $sessiondata, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
            $attempt->method('isBlocked')->willReturn($isBlocked);
            $attempt->method('addAttempt')->willReturn(true);
        
        $user = $this->getMockBuilder('mockUser')->getMock();
            $user->method('getUID')->willReturn($getUID);
            $user->method('getUser')->willReturn($getUser);
        
        $session = $this->getMockBuilder('mockSession')->getMock();
            $session->method('addSession')->willReturn($sessiondata);
        
        $auth = new Auth($dbh, $config, $user, $session, $request, $attempt); 
        
        $this->assertEquals($result, $auth->login($username, $password, $remember));

    }
    
    public function getRegisterDataProvider()
    {
        $validateEmail = 'validate@email.com';
        $validatePass = 'Validate-Pass_123';
        
        return array(
                array(true, $validatePass, $validateEmail, false, 1, true, array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED)),
                array(false, $validatePass, $validateEmail, false, 1, true, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_PASSWORD_NOMATCH)),
                array(false, $validatePass, $validateEmail, $validatePass, 1, true, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_EMAIL_TAKEN)),
                array(false, $validatePass, $validateEmail, $validatePass, 0, true, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_USERNAME_TAKEN)),
                array(false, $validatePass, $validateEmail, $validatePass, 0, false, array('error' => 0, 'message' => 'register_success'))
            );
    }

    /**
     * @dataProvider getRegisterDataProvider
     */
    public function testRegister($isBlocked, $password, $email, $repeatpassword, $rowCount, $getUID, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        $config->table_users = 'table_users';
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
            $attempt->method('isBlocked')->willReturn($isBlocked);
            $attempt->method('addAttempt')->willReturn(true);
        
        $user = $this->getMockBuilder('mockUser')->getMock();
            $user->method('getUID')->willReturn($getUID);
        
        $session = $this->getMockBuilder('mockSession')->getMock();
        
        $auth = new Auth($dbh, $config, $user, $session, $request, $attempt);
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();
            $statement->method('rowCount')->willReturn($rowCount);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $auth->register($email, 'username', $password, $repeatpassword));
    }
    
    public function getResendActivationDataProvider()
    {
        return array(
                array(true, 0, array('isactive' => 1), array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED)),
                array(false, 0, array('isactive' => 1), array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_EMAIL_INCORRECT)),
                array(false, 1, array('isactive' => 1), array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_ALREADY_ACTIVATED)),
                array(false, 1, array('isactive' => 0), array('error' => 0, 'message' => 'activation_sent'))
            );
    }

    /**
     * @dataProvider getResendActivationDataProvider
     */
    public function testResendActivation($isBlocked, $rowCount, $getUser, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        $config->table_users = 'table_users';
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
            $attempt->method('isBlocked')->willReturn($isBlocked);
            $attempt->method('addAttempt')->willReturn(true);
        
        $user = $this->getMockBuilder('mockUser')->getMock();
            $user->method('getUser')->willReturn($getUser);
        
        $session = $this->getMockBuilder('mockSession')->getMock();
        
        $auth = new Auth($dbh, $config, $user, $session, $request, $attempt);
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();
            $statement->method('rowCount')->willReturn($rowCount);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $auth->resendActivation('validate@email.com'));
    }
}
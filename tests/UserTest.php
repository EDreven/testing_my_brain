<?php
include_once __DIR__ . '\..\User.php';
include_once __DIR__ . '\..\Request.php';
include_once __DIR__ . '\..\Attempt.php';

class mockAttempt extends Attempt
{
    public function __construct ()
    {}
}
class mockRequest extends Request
{
    public function __construct ()
    {}
}

class UserTest extends PHPUnit_Framework_TestCase
{
    public function getDeleteUserDataProvider()
    {
        $validatePass = 'Validate-Pass_123';
        
        return array(
            array(true, $validatePass, false, false, array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED )),
            array(false, $validatePass, false, false, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_PASSWORD_INCORRECT )),
            array(false, $validatePass, true, false, array('error' => 1, 'message' => AuthException::ERROR_AUTH_SYSTEM_ERROR )),
            array(false, $validatePass, true, true, array('error' => 0, 'message' => 'account_deleted' )),

        );
    }

    /**
     * @dataProvider getDeleteUserDataProvider
     */
    public function testDeleteUser($isBlocked, $password, $getUser, $execute, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
            $config->table_users = 'table_users';
            $config->table_sessions = 'table_sessions';
            $config->table_requests = 'table_requests';
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
            $request->method('getUser')->willReturn(array('password' => $getUser));
            
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
            $attempt->method('isBlocked')->willReturn($isBlocked);
            $attempt->method('addAttempt')->willReturn(true);
        
        $user = new User($dbh, $config, $request, $attempt); 
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();
            $statement->method('execute')->willReturn($execute);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $user->deleteUser(1, $password));

    }

    public function getResetPassDataProvider()
    {
        $validatePass = 'Validate-Pass_123';
        
        return array(
            array(true, false, false, 0, array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED )),
            array(false, false, false, 0, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH )),
            array(false, $validatePass, false, 0, array('error' => 1, 'message' => AuthException::ERROR_AUTH_SYSTEM_ERROR )),
            array(false, $validatePass, array('password' => $validatePass, 'salt' => ''), 0, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH )),
            array(false, $validatePass, array('password' => false, 'salt' => ''), 0, array('error' => 1, 'message' => AuthException::ERROR_AUTH_SYSTEM_ERROR )),
            array(false, $validatePass, array('password' => false, 'salt' => ''), 1, array('error' => 0, 'message' => 'password_reset' )),
        );
    }

    /**
     * @dataProvider getResetPassDataProvider
     */
    public function testResetPass($isBlocked, $repeatpassword, $getUser, $rowCount, $result)
    {
        $validatePass = 'Validate-Pass_123';
        $validateKey = '12345678901234567890';
        
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
            $config->table_users = 'table_users';
            $config->table_sessions = 'table_sessions';
            $config->table_requests = 'table_requests';
            $config->bcrypt_cost = 'bcrypt_cost';
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
            $request->method('getUser')->willReturn($getUser);
            $request->method('getRequest')->willReturn(true);
            $request->method('deleteRequest')->willReturn(true);
            
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
            $attempt->method('isBlocked')->willReturn($isBlocked);
            $attempt->method('addAttempt')->willReturn(true);
        
        $user = new User($dbh, $config, $request, $attempt); 
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();
            $statement->method('rowCount')->willReturn($rowCount);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $user->resetPass($validateKey, $validatePass, $repeatpassword));

    }
}
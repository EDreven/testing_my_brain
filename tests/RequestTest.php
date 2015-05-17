<?php
include_once __DIR__ . '\..\Request.php';

class mockAttempt extends Attempt
{
    public function __construct ()
    {}
}

class RequestTest extends PHPUnit_Framework_TestCase
{
    public $request;
    
    public function getRequestDataProvider()
    {
        return array(
            array(0, date("Y-m-d H:i:s"), 1, 1, AuthException::ERROR_VALIDATE_KEY_INCORRECT),
            array(1, date("Y-m-d H:i:s", strtotime("-1 minutes")), 1, 1, AuthException::ERROR_VALIDATE_KEY_EXPIRED),
            array(1, date("Y-m-d H:i:s", strtotime("+1 minutes")), 1, 1, true),
        );
    }
    
    /**
     * @dataProvider getRequestDataProvider
     */
    public function testGetRequest($rowCount, $expire, $id, $uid, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        $config->table_requests = 'table_requests';
        
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
        $attempt->method('addAttempt')->willReturn(true);
        
        $this->request = new Request($dbh, $config, $attempt); 
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();

            $statement->method('rowCount')->willReturn($rowCount);
            $statement->method('fetch')->willReturn(array('expire' => $expire, 'id' => $id, 'uid' => $uid));
        
        $dbh->method('prepare')->willReturn($statement);
        
        try {
            $this->assertEquals(array('error' => 0, 'id' => $id, 'uid' => $uid), $this->request->getRequest(1, 1));
        } catch (AuthException $ex) {
            $this->assertEquals($result, $ex->getMessage());
        }
    }
        
    public function requestResetDataProvider()
    {
        return array(
            array(true, '@@@', 0, array('error' => 1, 'message' => AuthException::ERROR_USER_BLOCKED)),
            array(false, '@@@', 0, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_EMAIL_INVALID)),
            array(false, 'valid@email.com', 0, array('error' => 1, 'message' => AuthException::ERROR_VALIDATE_EMAIL_INCORRECT)),
            array(false, 'valid@email.com', 1, array('error' => 0, 'message' => 'reset_requested')),
//            array(false, date("Y-m-d H:i:s", strtotime("+1 minutes")), 1, 1, true),
        );
    }
    
    /**
     * @dataProvider requestResetDataProvider
     */
    public function testRequestReset($isBlocken, $email, $rowCount, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        $config->table_users = 'table_users';
        $config->table_requests = 'table_requests';
        $config->site_name = 'site_name';
        $config->site_url = 'site_url';
        $config->site_email = 'site_email';
        
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
        $attempt->method('isBlocked')->willReturn($isBlocken);
        
        $this->request = new Request($dbh, $config, $attempt); 
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();

            $statement->method('rowCount')->willReturn($rowCount);
            $statement->method('fetch')->willReturn(array('id' => 1, 'expire' => date("Y-m-d H:i:s")));
            $statement->method('execute')->willReturn(true);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $this->request->requestReset($email) );
    }
}
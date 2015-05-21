<?php
include_once __DIR__ . '\..\Session.php';
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

class SessiontTest extends PHPUnit_Framework_TestCase
{
    public $attempt;
    public $request;
    
    public function getCheckSessionDataProvider()
    {
        $trueCookie_crc = sha1('0123456789012345678901234567890123456789' . 'site_key');
        $row = array(
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s", strtotime("-1 minutes")), 'ip' => null, 'agent' => null, 'cookie_crc' => null ),
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s", strtotime("+1 minutes")), 'ip' => null, 'agent' => null, 'cookie_crc' => null ),
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s"), 'ip' => '127.0.0.1', 'agent' => null, 'cookie_crc' => null ),
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s"), 'ip' => '127.0.0.1', 'agent' => 'HTTP_USER_AGENT', 'cookie_crc' => null ),
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s"), 'ip' => '127.0.0.1', 'agent' => 'HTTP_USER_AGENT', 'cookie_crc' => $trueCookie_crc ),
                    array('id' => 1, 'uid' => 1, 'expiredate' => date("Y-m-d H:i:s"), 'ip' => null, 'agent' => 'HTTP_USER_AGENT', 'cookie_crc' => $trueCookie_crc ),
                );
        
        return array(
            array('01234567890', true, 0, $row[0], false),
            array('0123456789012345678901234567890123456789', true, 0, $row[0], false),
            array('0123456789012345678901234567890123456789', false, 0, $row[0], false),
            array('0123456789012345678901234567890123456789', false, 1, $row[0], false),
            
            array('0123456789012345678901234567890123456789', false, 1, $row[0], false),
            array('0123456789012345678901234567890123456789', false, 1, $row[1], false),
            array('0123456789012345678901234567890123456789', false, 1, $row[2], false),
            array('0123456789012345678901234567890123456789', false, 1, $row[3], false),
            array('0123456789012345678901234567890123456789', false, 1, $row[4], true),
            array('0123456789012345678901234567890123456789', false, 1, $row[5], false),
        );
    }
    
    /**
     * @dataProvider getCheckSessionDataProvider
     */
    public function testcheckSession($hash, $isBlocked, $rowCount, $row, $result)
    {
        $_SERVER['HTTP_USER_AGENT'] = 'HTTP_USER_AGENT';
        $dbh = $this->getMockBuilder('mockPDO')->getMock();
        
        $config = new stdClass();
        $config->site_key = 'site_key';
        $config->table_sessions = 'table_sessions';
        
        $request = $this->getMockBuilder('mockRequest')->getMock();
        $attempt = $this->getMockBuilder('mockAttempt')->getMock();
        $attempt->method('isBlocked')->willReturn($isBlocked);
        $attempt->method('getIp')->willReturn($_SERVER['REMOTE_ADDR']);
        
        $this->session = new Session($dbh, $config, $request, $attempt); 
        
            $statement = $this->getMockBuilder('PDOStatement')->getMock();

            $statement->method('rowCount')->willReturn($rowCount);
//            $statement->method('fetch')->willReturn($row);
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $this->session->checkSession($hash));

    }
}
<?php
include_once __DIR__ . '\..\Attempt.php';

class AttemptTest extends PHPUnit_Framework_TestCase
{
    public $attempt;

    public function isBlockedDataProvider()
    {
        return array(
            array(0, date("Y-m-d H:i:s"), 1, false),
            array(1, date("Y-m-d H:i:s"), 1, false),
            array(1, date("Y-m-d H:i:s", strtotime("+30 minutes")), 1, false),
            array(1, date("Y-m-d H:i:s", strtotime("+30 minutes")), 5, true)
        );
    }
    
    /**
     * @dataProvider isBlockedDataProvider
     */
    public function testisBlocked($rowCount, $expiredate, $count, $result)
    {
        $dbh = $this->getMockBuilder('mockPDO')
                     ->getMock();
        
        $config = new stdClass();
        $config->table_attempts = 'table_attempts';

        $this->attempt = new Attempt($dbh, $config); 
        
            $statement = $this->getMockBuilder('PDOStatement')
                               ->getMock();

            $statement->method('rowCount')->willReturn($rowCount);
            $statement->method('fetch')->willReturn(array('expiredate' => $expiredate, 'count' => $count));
        
        $dbh->method('prepare')->willReturn($statement);
        
        $this->assertEquals($result, $this->attempt->isBlocked());
    }
}
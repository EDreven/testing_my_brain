<?php

require (__DIR__).'\\Composer\\vendor\\autoload.php';

date_default_timezone_set('Europe/Moscow');

class mockPDO extends PDO
{
    public function __construct ()
    {}
}

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
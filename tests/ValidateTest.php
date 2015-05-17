<?php
include_once __DIR__ . '\..\Validate.php';

class ValidateTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException        AuthException
     * @expectedExceptionMessage AuthException::ERROR_VALIDATE_USERNAME_BANNED
     */
    function testValidateUsernameBanned()
    {
        Validate::validateUsernameBanned('BanedUserNameTwo');
    }

    public function validateUsernameDataProvider()
    {
        return array(
            array('Eric', true),
            array('', AuthException::ERROR_VALIDATE_USERNAME_SHORT),
            array('1234567890123456789012345678901', AuthException::ERROR_VALIDATE_USERNAME_LONG),
            array('Eric%', AuthException::ERROR_VALIDATE_USERNAME_INVALID),
            array('1234567890123456789012345678901', AuthException::ERROR_VALIDATE_USERNAME_LONG),
            array('1234567890123456789012345678901', AuthException::ERROR_VALIDATE_USERNAME_LONG),
        );
    }
    
    /**
     * @dataProvider validateUsernameDataProvider
     */
    function testValidateUsername($string, $result)
    {
        try {
            Validate::validateUsername($string);
            $this->assertTrue($result);
        } catch (AuthException $ex) {
            $this->assertEquals($result, $ex->getMessage());
        }
    }

    public function validatePasswordDataProvider()
    {
        return array(
            array('Password_1', true),
            array('12345', AuthException::ERROR_VALIDATE_PASSWORD_SHORT),
            array('VeryLongPassword_12345678901234567890123456789012345678901234567890123456789012345678901234567890', AuthException::ERROR_VALIDATE_PASSWORD_LONG),
            array('invalid_password1', AuthException::ERROR_VALIDATE_PASSWORD_INVALID),
            array('некорректный_пароль', AuthException::ERROR_VALIDATE_PASSWORD_INVALID),
            array('!@#$%^&*()', AuthException::ERROR_VALIDATE_PASSWORD_INVALID),
            array('Invalidpassword', AuthException::ERROR_VALIDATE_PASSWORD_INVALID),
            array('1234567', AuthException::ERROR_VALIDATE_PASSWORD_INVALID),
        );
    }
    
    /**
     * @dataProvider validatePasswordDataProvider
     */
    function testValidateRassword($string, $result)
    {
        try {
            Validate::validatePassword($string);
            $this->assertTrue($result);
        } catch (AuthException $ex) {
            $this->assertEquals($result, $ex->getMessage());
        }
    }
   
        
    public function validateEmailDataProvider()
    {
        return array(
            array('Email.validade@ok.com', true),
            array('@.r', AuthException::ERROR_VALIDATE_EMAIL_SHORT),
            array('VeryLongEmail.1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890@very.ru', AuthException::ERROR_VALIDATE_EMAIL_LONG),
            array('некорректный@email.com', AuthException::ERROR_VALIDATE_EMAIL_INVALID),
            array('invalid@.com', AuthException::ERROR_VALIDATE_EMAIL_INVALID),
            array('invalid.com', AuthException::ERROR_VALIDATE_EMAIL_INVALID),
            array('banned2@email.com', AuthException::ERROR_VALIDATE_EMAIL_BANNED),
        );
    }
    
    /**
     * @dataProvider validateEmailDataProvider
     */
    function testValidateEmail($string, $result)
    {
        try {
            Validate::validateEmail($string);
            $this->assertTrue($result);
        } catch (AuthException $ex) {
            $this->assertEquals($result, $ex->getMessage());
        }
    }
        
    public function validateKeyDataProvider()
    {
        return array(
            array('Валидный_key_REALY!!', true),
            array('noValidKey', AuthException::ERROR_VALIDATE_KEY_INVALID),
        );
    }
    
    /**
     * @dataProvider validateKeyDataProvider
     */
    function testValidateKey($string, $result)
    {
        try {
            Validate::validateKey($string);
            $this->assertTrue($result);
        } catch (AuthException $ex) {
            $this->assertEquals($result, $ex->getMessage());
        }
    }  
}
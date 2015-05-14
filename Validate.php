<?php

class Validate
{
    static function validateUsername($username) {
        if (strlen($username) < 3) {
            throw new AuthException(AuthException::ERROR_VALIDATE_USERNAME_SHORT, 1);
        } elseif (strlen($username) > 30) {
            throw new AuthException(AuthException::ERROR_VALIDATE_USERNAME_LONG, 1);
        } elseif (!ctype_alnum($username)) {
            throw new AuthException(AuthException::ERROR_VALIDATE_USERNAME_INVALID, 1);
        }
    }
    
    static function validateUsernameBanned($username) {
        $bannedUsernames = file(__DIR__ . "/files/banned-usernames.txt", FILE_IGNORE_NEW_LINES);
        if (in_array(strtolower($username), $bannedUsernames)) {
            throw new AuthException(AuthException::ERROR_VALIDATE_USERNAME_BANNED, 1);
        }
    }
    
    static function validatePassword($password) {

        if (strlen($password) < 6) {
            throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_SHORT, 1);
        } elseif (strlen($password) > 72) {
            throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_LONG, 1);
        } elseif (!preg_match('@[A-Z]@', $password) || !preg_match('@[a-z]@', $password) || !preg_match('@[0-9]@', $password)) {
            throw new AuthException(AuthException::ERROR_VALIDATE_PASSWORD_INVALID, 1);
        }
    }
    
    static function validateEmail($email) {

        if (strlen($email) < 5) {
            throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_SHORT, 1);
        } elseif (strlen($email) > 100) {
            throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_LONG, 1);
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_INVALID, 1);
        }

        $bannedEmails = file(__DIR__ . "/files/banned-emails.txt", FILE_IGNORE_NEW_LINES);

        if (in_array(strtolower($email, $bannedEmails))) {
            throw new AuthException(AuthException::ERROR_VALIDATE_EMAIL_BANNED, 1);
        }
    }
    
    static function validateKey($key) {
        if(strlen($key) !== 20) {
            throw new AuthException(AuthException::ERROR_VALIDATE_KEY_INVALID, 1);
	}
    }
    
}   

<?php

class AuthException extends Exception
{
    const ERROR_AUTH_USERNAME_PASSWORD_INVALID = 'username_password_invalid';
    const ERROR_AUTH_USERNAME_PASSWORD_INCORRECT = 'username_password_incorrect';
    const ERROR_AUTH_REMEMBER_ME_INVALID = 'remember_me_invalid';
    const ERROR_AUTH_ACCOUNT_INACTIVE = 'account_inactive';
    const ERROR_AUTH_SYSTEM_ERROR = 'system_error';

    const ERROR_VALIDATE_USERNAME_BANNED = 'username_banned';
    const ERROR_VALIDATE_USERNAME_SHORT = 'username_short';
    const ERROR_VALIDATE_USERNAME_LONG = 'username_long';
    const ERROR_VALIDATE_USERNAME_INVALID = 'username_invalid';
    const ERROR_VALIDATE_USERNAME_TAKEN = 'username_taken';
    
    const ERROR_VALIDATE_EMAIL_BANNED = 'email_banned';
    const ERROR_VALIDATE_EMAIL_SHORT = 'email_short';
    const ERROR_VALIDATE_EMAIL_LONG = 'email_long';
    const ERROR_VALIDATE_EMAIL_INVALID = 'email_invalid';
    const ERROR_VALIDATE_EMAIL_TAKEN = 'email_taken';
    const ERROR_VALIDATE_EMAIL_NEWEMAIL_MATCH = 'newemail_match';
    const ERROR_VALIDATE_EMAIL_INCORRECT = 'email_incorrect';
    
    const ERROR_VALIDATE_PASSWORD_SHORT = 'password_short';
    const ERROR_VALIDATE_PASSWORD_LONG = 'password_long';
    const ERROR_VALIDATE_PASSWORD_INVALID = 'password_invalid';
    const ERROR_VALIDATE_PASSWORD_INCORRECT = 'password_incorrect';
    const ERROR_VALIDATE_PASSWORD_NOMATCH = 'password_nomatch';
    const ERROR_VALIDATE_PASSWORD_NEWPASSWORD_NOMATCH = 'newpassword_nomatch';
    const ERROR_VALIDATE_PASSWORD_NEWPASSWORD_MATCH = 'newpassword_match';
    const ERROR_VALIDATE_PASSWORD_NOTVALID = 'password_notvalid';
    
    const ERROR_VALIDATE_KEY_INVALID = 'key_invalid';
    const ERROR_VALIDATE_KEY_EXPIRED = 'key_expired';
    const ERROR_VALIDATE_KEY_INCORRECT = 'key_incorrect';
    
    const ERROR_VALIDATE_ALREADY_ACTIVATED = 'already_activated'; 
    const ERROR_USER_BLOCKED = 'user_blocked';
    const ERROR_REQUEST_EXISTS = 'request_exists';
}


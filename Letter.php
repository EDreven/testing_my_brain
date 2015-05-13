<?php

class Letter {

    var $email = "";
    var $username = "";
    var $password = "";
    var $hash = "";
    var $hrefs = "";
    var $type = "";
    var $user_2 = "";
    var $item_id = "";
    var $title = "";
    var $message = "";
    var $HTMLLetter = "";
    var $unsubscribe = true;
    var $headers = "MIME-Version: 1.0\r\nContent-type: text/html; Charset=utf-8\r\nFrom:support@domain.com\r\n";

        
    function SendMail($email, $title, $HTMLLetter, $headers)
    {
        return mail($email, $title, $HTMLLetter, $headers);
    }
    
    function Send() {
        switch ($this->type) {

            case "Login":
                $this->title = "Domain Login Info";
                $this->message = "
                    You've requested your login information on Domain.com<br><br>
                    Here they are:<br><br>
                    Username: " . $this->username . "<br>
                    Password: " . $this->password . " ";
                break;


            case "Reset":
                $this->title = "Domain Login Info";
                $resetHref = "http://www.domain.com/reset/?user=" . urlencode($this->username) . "&hash=" . urlencode($this->hash);
                $this->message = "
				Hello, {$this->username}<br><br>
				You have requested to reset your password on Domain.com because you have forgotten your username or password. If you did not request this, please ignore it.
				<br><br>
				To reset your password, please visit the following page:<br>
				<a href=\"{$resetHref}\">{$resetHref}</a>
				<br><br>
				When you visit that page, your password will be reset, and the new password will be emailed to you.
				<br><br>
				To edit your profile, go to this page:<br>
				<a href=\"http://www.domain.com/account\">http://www.domain.com/account</a><br>";
                break;

            case "Newpass":
                $this->title = "Domain New password";
                $this->message = "
				Hello, {$this->username}
				<br><br>
				As you requested, your password has now been reset. Your new details are as follows:<br>
				Username: {$this->username}<br>
				Password: {$this->password}
				<br><br>
				You can change your new password in your profile:<br>
				<a href=\"http://www.domain.com/account\">http://www.domain.com/account</a><br>";
                break;

            case "Corrected":
                $this->title = "Someone corrected your item";
                $this->message = "
                    Domain's user " . $this->user_2 . " has corrected your item :<br>
                    <a href=\"http://www.domain.com/item/" . $this->item_id . "\">http://www.domain.com/item/" . $this->item_id . "</a>.<br><br>
                    Please click <a href=\"http://www.domain.com/item/" . $this->item_id . "\">here</a> to accept or reject a correction.";
                break;

            case "SubmittedRejected":
                $this->title = "Your submitted item wasn't accepted";
                $this->message = "
                    Your <b>" . $this->item_id . "</b> item was rejected by our moderators<br>
                    because one of the following reasons :<br><br>
                    1. You item were formatted wrong<br>
                    2. These item doesn't seem to belong to the category you specified.";
                break;

            case "SubmittedRejected2":
                $this->title = "Your submitted item wasn't accepted";
                $this->message = "
                    Your <b>" . $this->item_id . "</b> item was rejected by our moderators<br>
                    because we already have this item in our database:<br>
                    <a href=\"http://www.domain.com/item/" . $this->item_id . "\">http://www.domain.com/item/" . $this->item_id . "</a> item";
                break;

            case "SubmittedAccepted":
                $this->title = "Your submitted item was accepted";
                $this->message = "
                    Your <b>" . $this->item_id . "</b> item was reviewed and approved<br>
                    by our moderators. You can view it <a href=\"http://www.domain.com/item/" . $this->item_id . "\">here</a>.<br><br>
                    Also you got " . submits_points . " points for this submittion.<br>
                    To view Domain's user stat check out your <a href=\"http://www.domain.com/items\">items</a>.";
                break;

            case "Updates":
                $this->title = "Your Domain updates";
                $this->message = "
                    It's the notification that Domain.com has been recently updated and new items were added.<br>
                    " . $this->hrefs . "";
                break;

            case "CorrectionsAcc":
                $this->title = "Your corrections have been accepted";
                $this->message = "
                    It's the notification that your corrections for <b>" . $this->item_id . "</b> item<br>
                    has been accepted. You can view corrected item at <a href=\"http://www.domain.com/item/" . $this->item_id . "\">this location</a>.";
                break;

            case "CorrectionsRejUser":
                $this->title = "Your corrections was rejected";
                $this->message = "
                    It's the notification that your corrections for <b>" . $this->item_id . "</b> item<br>
                    has been declined by <a href=\"http://www.domain.com/user/" . strtolower($this->user_2) . "\">" . $this->user_2 . "</a>.";
                break;

            case "CorrectionsRejMod":
                $this->title = "Your corrections was rejected";
                $this->message = "
                    It's the notification that your corrections for <b>" . $this->item_id . "</b> item<br>
                    has been declined by our moderators.";
                break;

            case "Subsription":
                $this->title = "Subscription for requested item";
                $this->message = "
                    We're glad to let you know that the item you've requested recently<br>
                    has been added to the site:<br><br>
                    <a href=\"http://www.domain.com/item/" . $this->item_id . "\">http://www.domain.com/item/" . $this->item_id . "</a>";
                break;

            case "SubscriptionUpcoming":
                $this->title = "Subscription for upcoming item";
                $this->message = "
                    We're glad to let you know that the upcoming item you've subscribed recently has been added to the site:" .
                    "<a href=\"http://www.domain.com/item/" . $this->item_id . "\">http://www.domain.com/item/" . $this->item_id . " item</a>";
                break;
        }

        if (strlen($this->username) > 0) {
            $this->username = " " . $this->username;
        }
        $this->HTMLLetter = "
            <p>Hello" . $this->username . ",
            <p><br>
            <!--MESSAGE-->
            " . $this->message . "
            <!--/MESSAGE-->
            <p>
            <i>---<br>Domain inc.</i>
            <p>" .
                ($this->unsubscribe ? "<font size=-1>If you want to unsubscribe from email notifications <a href=\"http://www.domain.com/account\" target='_blank'>click here</a></font>" : "") .
                "</html>";

        $this->SendMail($this->email, $this->title, $this->HTMLLetter, $this->headers);
    }


}

?>
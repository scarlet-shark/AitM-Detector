<?php
/**
 * A PHP script to detect Attacker-in-the-Middle (AitM) phishing on Microsoft 365 login pages.
 *
 * This file is meant to be run from an Azure PHP App service.
 *
 * @author    Alec Dhuse
 * @license   https://www.gnu.org/licenses/ GNU Affero General Public License v3.0
 * @link      https://github.com/scarlet-shark/AitM-Detector/
 */

  // Includes for Email notifications, remove if not used.
  include_once 'PHPMailer/PHPMailer.php';
  include_once 'PHPMailer/SMTP.php';
  include_once 'PHPMailer/Exception.php';

  use PHPMailer\PHPMailer\PHPMailer;
  use PHPMailer\PHPMailer\SMTP;
  use PHPMailer\PHPMailer\Exception;

  // Referal domains that will not trigger an alert.
  $safe_referrers = array(
    "[NONE]", // Include this to reduce false positives.
    "login.microsoftonline.com",
    "login.microsoft.com",
    "autologon.microsoftazuread-sso.com"
  );

  // Return a 1x1 transparent image.
  header('Referrer-Policy: origin');
  header('Content-Type: image/png');
  echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZgAAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');

  $client_ip = $_SERVER['HTTP_CLIENT_IP'] ? : ($_SERVER['HTTP_X_FORWARDED_FOR'] ? : $_SERVER['REMOTE_ADDR']);

  // Check for port number on IP and strip it off if it exists.
  if (preg_match('/^\[(.+)\]:\d+$/', $client_ip, $matches)) {
      $client_ip = $matches[1]; // IPv6 case
  } elseif (substr_count($client_ip, '.') === 3 && strpos($client_ip, ':') !== false) {
      $client_ip = explode(':', $client_ip)[0]; // IPv4 case
  }

  $referrer_domain = (isset($_SERVER['HTTP_REFERER']) ? strval($_SERVER['HTTP_REFERER']) : "");
  $user_lang = (isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? strval($_SERVER['HTTP_ACCEPT_LANGUAGE']) : "");
  $user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? strval($_SERVER['HTTP_USER_AGENT']) : "");
  $user_charset = (isset($_SERVER['HTTP_ACCEPT_CHARSET']) ? strval($_SERVER['HTTP_ACCEPT_CHARSET']) : "");

  if ($referrer_domain === "") {
    $phishing_domain = "[NONE]";
    $phishing_domain_defang = $phishing_domain;
  } else {
    $phishing_domain = strtolower(parse_url($referrer_domain, PHP_URL_HOST) ?? "unknown");
    $phishing_domain_defang = str_replace(".", "[.]", $phishing_domain);
  }

  // Check to see if the referal / phishing domain is in the allowed referrers array.
  if (!in_array($phishing_domain, $safe_referrers)) {
    // Referal domain is not in the safe list, trigger AitM actions.
    $page_load_time = gmdate('Y-m-d H:i:s ') . "UTC";

    // Add any cutom\ enrichment code here.

    // Get Email auth info from environment variables. Remove if not using email alerts.
    $smtp_server = getenv("SMTP_SERVER"); // The hostname or IP of the SMTP server used to send alerts.
    $sender_email = getenv("SMTP_SENDER_EMAIL"); // The email address that will be sending the alert email.
    $sender_password = getenv("SMTP_PASSWORD"); // The password for the sender email on the SMTP server.
    $destination_email = getenv("DESTINATION_EMAIL"); // The recipient of the alert email.

    // Set the email message information, modify or remove as nessesary.
    $email_subject = "AitM Phishing Page Detected";
    $email_html_body = "An AitM phishing page has been detected. \n<br>\n<br><b>Details:</b>\n<br>Phishing Domain: $phishing_domain_defang \n<br> Victim's IP: $client_ip \n<br> User Agent: $user_agent \n<br> Phishing Page Accessed By Victim At: $page_load_time";
    $email_plain_text_body = "An AitM phishing page has been detected. \n\nDetails:\nPhishing Domain: $phishing_domain_defang \n Victim's IP: $client_ip \n User Agent: $user_agent \n Phishing Page Accessed By Victim At: $page_load_time";

    // Send email alert
    try {
      $mail = new PHPMailer(true);
      $mail->SMTPDebug = false;
      $mail->isSMTP();
      $mail->Host       = $smtp_server;
      $mail->SMTPAuth   = true;
      $mail->Username   = $sender_email;
      $mail->Password   = $sender_password;
      $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
      $mail->Port       = 587;

      //Recipients
      $mail->setFrom($sender_email, 'Alerts');
      $mail->addAddress($destination_email);
      $mail->addReplyTo($sender_email, 'Alerts');

      //Content
      $mail->isHTML(true);
      $mail->Subject = $email_subject;
      $mail->Body    = $email_html_body;
      $mail->AltBody = $email_plain_text_body;

      $mail->send();
    } catch (Exception $e) {
        // Failed to send email.
        // Add any logging code here.
    }
  } else {
    // Referal domain is in the safe list.
  }
?>

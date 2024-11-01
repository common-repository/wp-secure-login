<?php
/**
 * @package wp-secure-login
 * @version 1.1
 */
/*
Plugin Name: WP Secure Login
Plugin URI: http://wordpress.org/extend/plugins/wp-secure-login/
Description: WP Secure Login adds a security layer and 2 step authentication to your WordPress site by asking a One Time Password in addition to the username and password on the login page. The One Time Password is displayed on your smartphone using Google Authenticator app (available in market place for FREE). The One Time Password is re-generated at regular intervals which can be customized from admin panel. As soon as the new OTP is generated the old ones are marked as invalid.
Version: 1.1
Author: Brijesh Kothari
Author URI: http://www.wpinspired.com/
License: GPLv3 or later
*/

/*
Copyright (C) 2013  Brijesh Kothari (email : admin@wpinspired.com)
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

if(!function_exists('add_action')){
	echo 'You are not allowed to access this page directly.';
	exit;
}

include_once('includes/functions.php');
include_once('includes/GoogleAuthenticator.php');

add_action('login_form', 'wpsl_login_form');

function wpsl_login_form(){

$wpsl_otp_text = base64_decode(wpsl_get_option('wpsl_otp_text'));
$wpsl_otp_text = (!empty($wpsl_otp_text) ? $wpsl_otp_text : 'One Time Password');

$wpsl_otp_text_exp = base64_decode(wpsl_get_option('wpsl_otp_text_exp'));
$wpsl_otp_text_exp = (!empty($wpsl_otp_text_exp) ? $wpsl_otp_text_exp : '(Google Authenticator app on your phone)<br />
Not configured OTP yet ? Leave blank');

?>
<p>
<label for="wpsl_otp_field"><?php echo $wpsl_otp_text;?></label><br />
<font size="2px"><?php echo $wpsl_otp_text_exp;?></font>
<input type="password" class="input" name="wpsl_otp_field" id="wpsl_otp_field" />
</p>

<?php
}

add_filter('authenticate', 'wpsl_login_form_validate', 30, 3);

function wpsl_login_form_validate($user, $username, $password){
	
	global $wpdb;

	$return_value = $user;

	$wpsl_otp_invalid = base64_decode(wpsl_get_option('wpsl_otp_invalid'));
	$wpsl_otp_invalid = (!empty($wpsl_otp_invalid) ? $wpsl_otp_invalid : '<b>One Time Password</b> is invalid. Please try again.');
	
	if(!is_wp_error($user)){
		$auth_data = wpsl_selectquery("SELECT * FROM `".$wpdb->prefix."wpsl_auth` 
		WHERE `user_id` = '".$user->data->ID."' AND `status` = '1';");
		
		if(!empty($auth_data)){
			$wpsl_otp = wpsl_sanitize_variables($_POST['wpsl_otp_field']);
			$wpsl_otp_expire = wpsl_get_option('wpsl_otp_expire');
			$expire_otp = (!empty($wpsl_otp_expire) ? $wpsl_otp_expire : 2); // $expire_otp*30sec clock tolerance
			$wpsl_user_hash = wpsl_sanitize_variables($_GET['wpsl_hash']);
			
			$ga = new PHPGangsta_GoogleAuthenticator();
			$checkResult = $ga->verifyCode($auth_data['secret'], $wpsl_otp, $expire_otp);
			
			if($checkResult !== true && $wpsl_otp !== $auth_data['hash']){
				$return_value = new WP_Error('invalid_otp', $wpsl_otp_invalid );
			}
		}
	}
	
	return $return_value;
}

define('wpsl_version', '1.1');

// Ok so we are now ready to go
register_activation_hook( __FILE__, 'wp_secure_login_activation');

function wp_secure_login_activation(){

global $wpdb;
$sql = array();

$sql[] = "
--
-- Table structure for table `".$wpdb->prefix."wpsl_options`
--
CREATE TABLE IF NOT EXISTS `".$wpdb->prefix."wpsl_options` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `option_name` varchar(255) NOT NULL,
  `option_value` text NOT NULL,
  `updated` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `option_name` (`option_name`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;";

$sql[] = "
--
-- Table structure for table `".$wpdb->prefix."wpsl_auth`
--
CREATE TABLE IF NOT EXISTS `".$wpdb->prefix."wpsl_auth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `secret` text NOT NULL,
  `hash` text NOT NULL,
  `status` tinyint(2) NOT NULL DEFAULT '0',
  `updated` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;";

foreach($sql as $sk => $sv){
	$wpdb->query($sv);
}

wpsl_add_option('wpsl_version', wpsl_version);

}

add_action( 'plugins_loaded', 'wp_secure_login_update_check' );

function wp_secure_login_update_check(){

global $wpdb;

	$sql = array();
	$current_version = wpsl_get_option('wpsl_version');

	if($current_version < wpsl_version){
		foreach($sql as $sk => $sv){
			$wpdb->query($sv);
		}

		wpsl_update_option('wpsl_version', wpsl_version);
	}

}

add_action( 'profile_personal_options', 'wp_secure_login_setting_up' );
add_action( 'personal_options_update', 'wp_secure_login_setting_updated' );

function wp_secure_login_setting_updated($user_id){
	
	global $wpdb;
    $user = get_userdata($user_id);
	$ga = new PHPGangsta_GoogleAuthenticator();
	$auth_data = wpsl_selectquery("SELECT * FROM `".$wpdb->prefix."wpsl_auth` WHERE `user_id` = '".$user_id."';");
	
	if(!empty($auth_data['secret'])){
		$secret = $auth_data['secret'];
	}else{
		$secret = $ga->createSecret();
		$result = $wpdb->query("INSERT INTO `".$wpdb->prefix."wpsl_auth`
		SET `user_id` = '".$user_id."', `secret` = '".$secret."', `hash` = '".md5($user->data->user_login.time())."', `updated` = '".time()."'
		ON DUPLICATE KEY UPDATE `user_id` = '".$user_id."', `secret` = '".$secret."', `hash` = '".md5($user->data->user_login.time())."', `updated` = '".time()."';");
	}
	
	$qrCodeUrl = $ga->getQRCodeGoogleUrl(rawurlencode(get_option('blogname')), $secret);
	
	$wpsl_test_otp = wpsl_sanitize_variables($_POST['wpsl_test_otp']);
	
	if(!empty($wpsl_test_otp) && empty($auth_data['status'])){
		$wpsl_otp_expire = wpsl_get_option('wpsl_otp_expire');
		$expire_otp = (!empty($wpsl_otp_expire) ? $wpsl_otp_expire : 2); // $expire_otp*30sec clock tolerance
		$checkResult = $ga->verifyCode($secret, $wpsl_test_otp, $expire_otp);
		$site_url = get_bloginfo('wpurl');
		$blogname = get_option('blogname');
		
		if($checkResult){			
			$result = $wpdb->query("UPDATE `".$wpdb->prefix."wpsl_auth` 
			SET `status` = '1', `updated` = '".time()."'
			WHERE `secret` = '".$secret."' AND `user_id` = '".$user_id."';");
			//setcookie('wpsl_'.$user->user_login, 'wpsl_otp_success', time()+50, '/');
	        $subject = "WP Secure Login configured successfully : ".$blogname."";
			$status_message = "You have just made your account two times more secure! \n You have successfully configured WP Secure Login One Time Password. You will now be prompted to fill in One Time password while logging into your WordPress account, this One Time Password will appear on the Google Authenticator app on your smartphone. \n\n Keep this email safe for future reference if you change your phone or do not have access to the Google Authenticator app you can use the below Hash Key as One Time Password on your login screen and then reconfigure WP Secure Login One Time Password. \n Hash Key : ".$auth_data['hash']." \n Never share this hash key with anyone. \n\nThank you for using WP Secure Login One Time Password authentication. ";
		}else{
			//setcookie('wpsl_'.$user->user_login, 'wpsl_otp_failed', time()+50, '/');
	        $subject = "WP Secure Login configuration failed : ".$blogname."";
			$status_message = "The One Time Password entered was invalid! Please try again.";
		}
		
        $to = $user->user_email;
        $message = "Hello " .$user->display_name . ",\n\n".$status_message." \n\nPowered by WP Inspired\n
http://www.wpinspired.com\n".$site_url."";
        wp_mail( $to, $subject, $message);
	}else{
		//unset($_COOKIE['wpsl_'.$user->data->user_login]);
		//setcookie('wpsl_'.$user->user_login, '', time()-3600, '/');		
	}
}
    
function wp_secure_login_setting_up( $user ) {
	
	global $wpdb;
	
	if(isset($_GET['delid'])){
		$delid = (int) wpsl_sanitize_variables($_GET['delid']);		
		$wpdb->query("DELETE FROM ".$wpdb->prefix."wpsl_auth WHERE `user_id` = '".$user->data->ID."' AND `id` = '".$delid."'");
	}
		
	/*if($_COOKIE['wpsl_'.$user->data->user_login] == 'wpsl_otp_success'){
		wpsl_report_success(array('<b>Congratulations!</b> WP Secure Login has been configured successfully.'));
		unset($_COOKIE['wpsl_'.$user->data->user_login]);
		setcookie('wpsl_'.$user->user_login, '', time()-3600, '/');
	}elseif($_COOKIE['wpsl_'.$user->data->user_login] == 'wpsl_otp_failed'){
		wpsl_report_error(array('One Time Password is invalid! Please try again.'));
		unset($_COOKIE['wpsl_'.$user->data->user_login]);
		setcookie('wpsl_'.$user->user_login, '', time()-3600, '/');
	}*/
	
    $meta_value = get_user_meta( $user->ID, 'meta_key', true ); // $user contains WP_User object
	$ga = new PHPGangsta_GoogleAuthenticator();
	
	$auth_data = wpsl_selectquery("SELECT * FROM `".$wpdb->prefix."wpsl_auth` WHERE `user_id` = '".$user->data->ID."';");
	
	if(!empty($auth_data['secret'])){
		$secret = $auth_data['secret'];
	}else{
		$secret = $ga->createSecret();
		$result = $wpdb->query("INSERT INTO `".$wpdb->prefix."wpsl_auth`
		SET `user_id` = '".$user->ID."', `secret` = '".$secret."', `hash` = '".md5($user->data->name.time())."', `updated` = '".time()."'
		ON DUPLICATE KEY UPDATE `user_id` = '".$user->ID."', `secret` = '".$secret."', `hash` = '".md5($user->data->name.time())."', `updated` = '".time()."';");
	}
	
	$auth_data = wpsl_selectquery("SELECT * FROM `".$wpdb->prefix."wpsl_auth` WHERE `user_id` = '".$user->data->ID."';");
	$qrCodeUrl = $ga->getQRCodeGoogleUrl(rawurlencode(get_option('blogname')), $secret);
	$otp_status = (!empty($auth_data['status']) ? 1 : 0);
	
	/*$wpsl_test_otp = wpsl_sanitize_variables($_POST['wpsl_test_otp']);
	
	if(!empty($wpsl_test_otp)){
		$wpsl_otp_expire = wpsl_get_option('wpsl_otp_expire');
		$expire_otp = (!empty($wpsl_otp_expire) ? $wpsl_otp_expire : 2); // $expire_otp*30sec clock tolerance
		$checkResult = $ga->verifyCode($auth_data['secret'], $wpsl_test_otp, $expire_otp);
		
		if($checkResult){			
			$result = $wpdb->query("UPDATE `".$wpdb->prefix."wpsl_auth` 
			SET `status` = '1', `updated` = '".time()."'
			WHERE `secret` = '".$secret."' AND `user_id` = '".$user->ID."';");
		}
	}*/
    ?>
	<a name="wp_secure_login"></a>
    <h2>Set up WP Secure Login</h2>
    <table class="form-table" border="0">
		  <tr>
			<th scope="row" valign="top"><label for="wpsl_secret_url"><?php echo __('QR Code','wp-secure-login'); ?></label><br />
			<font size="-1">Download Google Authenticator app on your smart phone and scan this QR Code to setup WP Secure Login<br /><br />
			<a href="http://www.wpinspired.com/docs/Using_Google_Authenticator" target="_blank">How it works ?</a></font>
            </th>
			<td width="40%">
            	<img src="<?php echo $qrCodeUrl;?>" name="wpsl_secret_url" id="wpsl_secret_url" />
			</td>
			<td>
            	<a href="http://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8" target="_blank">
                <img src="<?php echo plugins_url('wp-secure-login/images/download-app-store.svg'); ?>" alt="Get it on Apple App Store" />
                </a><br /><br />
                <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank">
            	<img src="<?php echo plugins_url('wp-secure-login/images/download-google-play.png'); ?>" alt="Get it on Google Play Store" />
                </a><br /><br />
				Blackberry users can search and install <br />Google Authenticator app on their phone.
			</td>
		  </tr>
		  <tr>
          	<?php 
				if(!empty($otp_status)){
					?>
                    <th scope="row" valign="top"><?php echo __('WP Secure Login Configured','wp-secure-login'); ?></th>
                    <td colspan="2">                        
                      <?php echo __('WP Secure Login is already configured. <a href="profile.php?delid='.$auth_data['id'].'" onclick="return confirm(\'Are you sure you want to re-configure WP Secure Login ?\')">Re-Configure ?','wp-secure-login'); ?>
                    </td>
					<?php
					
				}else{
					?>
                    <th scope="row" valign="top"><label for="wpsl_test_otp"><?php echo __('One Time Password','wp-secure-login'); ?></label></th>
                    <td colspan="2">
                        <input type="text" size="25" value="<?php ((isset($_POST['wpsl_test_otp']) ? $_POST['wpsl_test_otp'] : '')) ?>" name="wpsl_test_otp" id="wpsl_test_otp" /><br />
                        
                      <?php echo __('Enter the One Time Password from Google Authenticator app on your smartphone<br />
						WP Secure Login will not work unless you Enter the OTP here and click on <b>Update Profile</b> button below.','wp-secure-login'); ?>
                    </td>
					<?php
				}
			?>
		  </tr>
		</table>
    <?php
}

add_action('admin_notices', 'wp_secure_login_admin_notices');

function wp_secure_login_admin_notices(){
	
	global $wpdb;
	
	$user_id = get_current_user_id();
	$auth_data = wpsl_selectquery("SELECT * FROM `".$wpdb->prefix."wpsl_auth` 
	WHERE `user_id` = '".$user_id."' AND `status` = '1';");
	
	if(empty($auth_data)){
		wpsl_report_notice(array('<b>Note:</b> You have not yet configured WP Secure Login One Time Password. <a href="profile.php#wp_secure_login" >Configure now.</a>'));
	}
}

// Add settings link on plugin page
function wp_secure_login_settings_link($links) { 
  $settings_link = '<a href="options-general.php?page=wp-secure-login">Settings</a>'; 
  array_unshift($links, $settings_link); 
  return $links; 
}
 
$plugin = plugin_basename(__FILE__); 
add_filter("plugin_action_links_$plugin", 'wp_secure_login_settings_link' );

add_action('admin_menu', 'wp_secure_login_admin_menu');

function wp_secure_login_admin_menu() {
	global $wp_version;

	// Modern WP?
	if (version_compare($wp_version, '3.0', '>=')) {
	    add_options_page('WP Secure Login', 'WP Secure Login', 'manage_options', 'wp-secure-login', 'wp_secure_login_option_page');
	    return;
	}

	// Older WPMU?
	if (function_exists("get_current_site")) {
	    add_submenu_page('wpmu-admin.php', 'WP Secure Login', 'WP Secure Login', 9, 'wp-secure-login', 'wp_secure_login_option_page');
	    return;
	}

	// Older WP
	add_options_page('WP Secure Login', 'WP Secure Login', 9, 'wp-secure-login', 'wp_secure_login_option_page');
}

function wp_secure_login_option_page(){

	global $wpdb;
	
	$error = array();
	
	if(!current_user_can('manage_options')){
		wp_die('Sorry, but you do not have permissions to change settings.');
	}

	/* Make sure post was from this page */
	if(count($_POST) > 0){
		check_admin_referer('wp-secure-login-options');
	}
	
	if(isset($_GET['delid'])){
		
		$delid = (int) wpsl_sanitize_variables($_GET['delid']);
		
		$wpdb->query("DELETE FROM ".$wpdb->prefix."wpsl_auth WHERE `id` = '".$delid."'");
		echo '<div id="message" class="updated fade"><p>'
			. __('Secret Key has been deleted successfully', 'wp-secure-login')
			. '</p></div>';	
	}
	
	if(isset($_POST['save_wpsl_settings'])){
		global $wp_secure_login_options;

		$wp_secure_login_options = array();
		$wp_secure_login_options['wpsl_otp_expire'] = (int) wpsl_sanitize_variables($_POST['wpsl_otp_expire']);
		$wpsl_otp_text = base64_encode(stripslashes(trim($_POST['wpsl_otp_text'])));
		$wpsl_otp_text_exp = base64_encode(stripslashes(trim($_POST['wpsl_otp_text_exp'])));
		$wpsl_otp_invalid = base64_encode(stripslashes(trim($_POST['wpsl_otp_invalid'])));
		
		$options['del_wpsl_otp_text'] = (wpsl_is_checked('del_wpsl_otp_text') ? 1 : 0);
		$options['del_wpsl_otp_text_exp'] = (wpsl_is_checked('del_wpsl_otp_text_exp') ? 1 : 0);
		$options['del_wpsl_otp_invalid'] = (wpsl_is_checked('del_wpsl_otp_invalid') ? 1 : 0);
		//print_r($wp_secure_login_options);
		
		if(empty($wp_secure_login_options['wpsl_otp_expire'])){
			$wp_secure_login_options['wpsl_otp_expire'] = 2;
		}
	
		if(!empty($options['del_wpsl_otp_text'])){
			wpsl_update_option('wpsl_otp_text', '');
			$_POST['wpsl_otp_text'] = '';
		}
	
		if(!empty($options['del_wpsl_otp_text_exp'])){
			wpsl_update_option('wpsl_otp_text_exp', '');
			$_POST['wpsl_otp_text_exp'] = '';
		}
	
		if(!empty($options['del_wpsl_otp_invalid'])){
			wpsl_update_option('wpsl_otp_invalid', '');
			$_POST['wpsl_otp_invalid'] = '';
		}
		
		if(empty($error)){
			
			$options['wpsl_otp_expire'] = $wp_secure_login_options['wpsl_otp_expire'];
			
			//wpsl_update_option('wpsl_otp_expire', $options['wpsl_otp_expire']);	
			
			wpsl_update_option('wpsl_otp_expire', $options['wpsl_otp_expire']);
		
			if(!empty($wpsl_otp_text) && empty($options['del_wpsl_otp_text'])){			
				wpsl_update_option('wpsl_otp_text', $wpsl_otp_text);			
			}
		
			if(!empty($wpsl_otp_text_exp) && empty($options['del_wpsl_otp_text_exp'])){			
				wpsl_update_option('wpsl_otp_text_exp', $wpsl_otp_text_exp);			
			}
		
			if(!empty($wpsl_otp_invalid) && empty($options['del_wpsl_otp_invalid'])){			
				wpsl_update_option('wpsl_otp_invalid', $wpsl_otp_invalid);			
			}
			
			echo '<div id="message" class="updated fade"><p>'
				. __('Settings have been saved successfully', 'wp-secure-login')
				. '</p></div>';
			
			
		}else{
			wpsl_report_error($error);
		}
	}
	
	if(isset($_POST['wpsl_filter_users'])){
		print_r($_POST);
	}
	
	$_wpsl_auth_data = $wpdb->get_results("SELECT * FROM ".$wpdb->prefix."wpsl_auth WHERE `status` = '1';", 'ARRAY_A');
	
	// Fill in the user id as key
	foreach($_wpsl_auth_data as $ak => $av){
		$__wpsl_auth_data[$av['user_id']] = $av;
	}
	
	$wpsl_otp_text = base64_decode(wpsl_get_option('wpsl_otp_text'));
	$wpsl_otp_text_exp = base64_decode(wpsl_get_option('wpsl_otp_text_exp'));
	$wpsl_otp_invalid = base64_decode(wpsl_get_option('wpsl_otp_invalid'));
	
	$users = get_users();
	//print_r($users);
	
	foreach($users as $uk => $uv){
		$wpsl_auth_data[$uv->data->ID] = $__wpsl_auth_data[$uv->data->ID];
		$wpsl_auth_data[$uv->data->ID]['user_data'] = $uv->data;
	}
	// Sort data 
	ksort($wpsl_auth_data);
	//print_r($wpsl_auth_data);
	
	$wpsl_otp_expire = wpsl_get_option('wpsl_otp_expire');
	
	$show_popup = 0;
	$donate_popup = wpsl_get_option('wpsl_donate_popup');
	if(!empty($donate_popup)){
		if($donate_popup <= date('Ymd', strtotime('-1 month'))){
			$show_popup = 1;
			wpsl_update_option('wpsl_donate_popup', date('Ymd'));
		}
	}else{
		$show_popup = 1;
		wpsl_update_option('wpsl_donate_popup', date('Ymd'));
	}
	
	echo '<script>
	var donate_popup = '.$show_popup.';
	if(donate_popup == 1){
		if(confirm("Donate $5 for WP Secure Login to support the development")){
			window.location.href =  "http://www.wpinspired.com/wp-secure-login";
		}
	}
	</script>';
	
	?>
	<div class="wrap">
	  <h2><?php echo __('WP Secure Login Settings','wp-secure-login'); ?></h2>
	  <form action="options-general.php?page=wp-secure-login" method="post">
		<?php wp_nonce_field('wp-secure-login-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><label for="wpsl_otp_expire"><?php echo __('One Time Password Expires','wp-secure-login'); ?></label></th>
			<td>
            	<select name="wpsl_otp_expire">
                	<option value="2" <?php if($wpsl_otp_expire == 2 || $_POST['wpsl_otp_expire'] == 2) echo 'selected="selected"'; ?> >1 Minute (Recommended)</option>
                	<option value="4" <?php if($wpsl_otp_expire == 4 || $_POST['wpsl_otp_expire'] == 4) echo 'selected="selected"'; ?> >2 Minutes</option>
                </select>
				<?php echo __('Choose the time for expiry of One Time password displayed on Google Authenticator app','wp-secure-login'); ?> <br />
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><label for="wpsl_otp_text"><?php echo __('Text for Login screen','wp-secure-login'); ?></label></th>
			<td>
            	<input type="text" size="25" value="<?php echo(htmlentities(isset($_POST['wpsl_otp_text']) ? stripslashes($_POST['wpsl_otp_text']) : (!empty($wpsl_otp_text) ? $wpsl_otp_text : ''))); ?>" name="wpsl_otp_text" id="wpsl_otp_text" /><br />
				<?php echo __('Enter the text that should be displayed on the Login screen','wp-secure-login'); ?> <br /><br />

                <?php if(!empty($wpsl_otp_text)){
					echo '<input type="checkbox" name="del_wpsl_otp_text" '.(wpsl_is_checked('del_wpsl_otp_text') ? 'checked="checked"' : '').' />';
					echo __('Choose this checkbox to use default text ','wp-secure-login');
				}
				?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><label for="wpsl_otp_text_exp"><?php echo __('Explanation for Login screen','wp-secure-login'); ?></label></th>
			<td>
            	<input type="text" size="25" value="<?php echo(htmlentities(isset($_POST['wpsl_otp_text_exp']) ? stripslashes($_POST['wpsl_otp_text_exp']) : (!empty($wpsl_otp_text_exp) ? $wpsl_otp_text_exp : ''))); ?>" name="wpsl_otp_text_exp" id="wpsl_otp_text_exp" /><br />
				<?php echo __('Enter the explanation that should be displayed on the Login screen','wp-secure-login'); ?> <br /><br />

                <?php if(!empty($wpsl_otp_text_exp)){
					echo '<input type="checkbox" name="del_wpsl_otp_text_exp" '.(wpsl_is_checked('del_wpsl_otp_text_exp') ? 'checked="checked"' : '').' />';
					echo __('Choose this checkbox to use default explanation ','wp-secure-login');
				}
				?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><label for="wpsl_otp_invalid"><?php echo __('Error Message if invalid OTP','wp-secure-login'); ?></label></th>
			<td>
            	<input type="text" size="25" value="<?php echo(htmlentities(isset($_POST['wpsl_otp_invalid']) ? stripslashes($_POST['wpsl_otp_invalid']) : (!empty($wpsl_otp_invalid) ? $wpsl_otp_invalid : ''))); ?>" name="wpsl_otp_invalid" id="wpsl_otp_invalid" /><br />
				<?php echo __('Enter the error message that should be displayed if One Time Password is invalid','wp-secure-login'); ?> <br /><br />

                <?php if(!empty($wpsl_otp_invalid)){
					echo '<input type="checkbox" name="del_wpsl_otp_invalid" '.(wpsl_is_checked('del_wpsl_otp_invalid') ? 'checked="checked"' : '').' />';
					echo __('Choose this checkbox to use default error message ','wp-secure-login');
				}
				?>
			</td>
		  </tr>
		</table><br />
		<input name="save_wpsl_settings" class="button action" value="<?php echo __('Save Settings','wp-secure-login'); ?>" type="submit" />		
	  </form>
	</div>	
	<?php
	//print_r($wpsl_auth_data);
	
	if(!empty($wpsl_auth_data)){
		?>
		<br /><br />
        <font size="+1">One Time Password Details</font><br /><br />
        <?php /*?><form action="options-general.php?page=wp-secure-login" method="post">
        	<?php wp_nonce_field('wp-secure-login-options'); ?>
	        <font size="+1">One Time Password Details</font> &nbsp;  &nbsp;  &nbsp;  &nbsp;  &nbsp;  &nbsp;  &nbsp; 
            <select name="filter_users">
                <option value="all" <?php if($_POST['filter_users'] == 'all') echo 'selected="selected"'; ?> >Show all users</option>
                <option value="otp" <?php if($_POST['filter_users'] == 'otp') echo 'selected="selected"'; ?> >Only OTP Configured users</option>
                <option value="no_otp" <?php if($_POST['filter_users'] == 'no_otp') echo 'selected="selected"'; ?> >No OTP Configured users</option>
            </select>  &nbsp;  &nbsp; 
            <select name="users_pagination">
                <option value="10" <?php if($_POST['users_pagination'] == '10') echo 'selected="selected"'; ?> >Show 10 users</option>
                <option value="20" <?php if($_POST['users_pagination'] == '20') echo 'selected="selected"'; ?> >Show 20 users</option>
                <option value="all" <?php if($_POST['filter_users'] == 'no_otp') echo 'selected="selected"'; ?> >Show all users</option>
            </select>  &nbsp;  &nbsp;
			<input name="wpsl_filter_users" class="button action" value="<?php echo __('Filter List','wp-secure-login'); ?>" type="submit" />
        </form><br /><?php */?>
		<table class="wp-list-table widefat fixed users" border="0">
			<tr>
				<th scope="row" valign="top"><?php echo __('<b>User ID</b>','wp-secure-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('<b>Username</b>','wp-secure-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('<b>One Time Password configured</b>','wp-secure-login'); ?></th>
				<th scope="row" valign="top"><?php echo __('<b>Options</b>','wp-secure-login'); ?></th>
			</tr>
			<?php
				
				foreach($wpsl_auth_data as $ik => $iv){
					$otp_status = '';
					$otp_status = (!empty($iv['secret']) ? 'Yes' : 'No');
					echo '
					<tr>
						<td>
							'.$ik.'
						</td>
						<td>
							'.$iv['user_data']->user_login.'
						</td>
						<td>
							'.$otp_status.'
						</td>
						<td>
							'.(!empty($iv['id']) ? '<a class="submitdelete" href="options-general.php?page=wp-secure-login&delid='.$iv['id'].'" onclick="return confirm(\'Are you sure you want to delete the secret key for this user ? User will have to configure One Time Password again.\')">Delete Secret Key</a>' : '<i>None</i>').'
						</td>
					</tr>';
				}
			?>
		</table>
		<?php
	}
	
	echo '<br /><br /><br /><br /><hr />
	WP Secure Login v'.wpsl_version.' is developed by <a href="http://wpinspired.com" target="_blank">WP Inspired</a>. 
	You can report any bugs <a href="http://wordpress.org/support/plugin/wp-secure-login" target="_blank">here</a>. 
	You can provide any valuable feedback <a href="http://www.wpinspired.com/contact-us/" target="_blank">here</a>.
	<a href="http://www.wpinspired.com/wp-secure-login" target="_blank">Donate</a>';
}	

// Sorry to see you going
register_uninstall_hook( __FILE__, 'wp_secure_login_deactivation');

function wp_secure_login_deactivation(){

global $wpdb;
$sql = array();

$sql[] = "DROP TABLE IF EXISTS `".$wpdb->prefix."wpsl_options`;";
$sql[] = "DROP TABLE IF EXISTS `".$wpdb->prefix."wpsl_auth`;";

$wpdb->query($sql);

foreach($sql as $sk => $sv){
	$wpdb->query($sv);
}

wpsl_delete_option('wpsl_version');
wpsl_delete_option('wpsl_dropdown');
wpsl_delete_option('wpsl_donate_popup');
wpsl_delete_option('wpsl_otp_expire');

}
?>

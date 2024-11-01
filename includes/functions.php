<?php

function wpsl_getip(){
	if(isset($_SERVER["REMOTE_ADDR"])){
		return $_SERVER["REMOTE_ADDR"];
	}elseif(isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
		return $_SERVER["HTTP_X_FORWARDED_FOR"];
	}elseif(isset($_SERVER["HTTP_CLIENT_IP"])){
		return $_SERVER["HTTP_CLIENT_IP"];
	}
}

function wpsl_get_option($option = ''){
	global $wpdb;
	
	$result = wpsl_selectquery("SELECT `option_value` FROM `".$wpdb->prefix."wpsl_options` WHERE `option_name` = '".$option."';");
	
	return $result['option_value'];
}

function wpsl_add_option($option = '', $value = ''){
	global $wpdb;
	
	$result = $wpdb->query("INSERT INTO `".$wpdb->prefix."wpsl_options` 
	SET `option_name` = '".$option."', `option_value` = '".$value."', `updated` = '".time()."'
	ON DUPLICATE KEY UPDATE `option_name` = '".$option."', `option_value` = '".$value."', `updated` = '".time()."';");
	
	if($result){
		return true;
	}else{
		return false;
	}
}

function wpsl_update_option($option = '', $value = ''){
	global $wpdb;
	
	$result = $wpdb->query("INSERT INTO `".$wpdb->prefix."wpsl_options` 
	SET `option_name` = '".$option."', `option_value` = '".$value."', `updated` = '".time()."'
	ON DUPLICATE KEY UPDATE `option_name` = '".$option."', `option_value` = '".$value."', `updated` = '".time()."';");
	
	if($result){
		return true;
	}else{
		return false;
	}
}

function wpsl_delete_option($option = ''){
	global $wpdb;
	
	$result = $wpdb->query("DELETE FROM `".$wpdb->prefix."wpsl_options` WHERE `option_name` = '".$option."';");
	
	if($result){
		return true;
	}else{
		return false;
	}
}

// update delete

function wpsl_selectquery($query){
	global $wpdb;
	
	$result = $wpdb->get_results($query, 'ARRAY_A');
	return current($result);
}

function wpsl_sanitize_variables($variables = array()){
	
	if(is_array($variables)){
		foreach($variables as $k => $v){
			$variables[$k] = trim($v);
			$variables[$k] = escapeshellcmd($v);
			$variables[$k] = mysql_real_escape_string($v);
		}
	}else{
		$variables = mysql_real_escape_string(escapeshellcmd(trim($variables)));
	}
	
	return $variables;
}

function wpsl_valid_ip($ip){

	if(!ip2long($ip)){
		return false;
	}	
	return true;
}

function wpsl_is_checked($post){

	if(!empty($_POST[$post])){
		return true;
	}	
	return false;
}

function wpsl_report_error($error = array()){

	if(empty($error)){
		return true;
	}
	
	$error_string = '<b>Please fix the below errors :</b> <br />';
	
	foreach($error as $ek => $ev){
		$error_string .= '* '.$ev.'<br />';
	}
	
	echo '<div id="message" class="error"><p>'
					. __($error_string, 'wp-secure-login')
					. '</p></div>';
}

function wpsl_report_success($message = array()){

	if(empty($message)){
		return true;
	}
	
	$message_string = '';
	
	foreach($message as $ek => $ev){
		$message_string .= $ev.'<br />';
	}
	
	echo '<div id="message" class="updated"><p>'
					. __($message_string, 'wp-secure-login')
					. '</p></div>';
}

function wpsl_report_notice($message = array()){

	if(empty($message)){
		return true;
	}
	
	$message_string = '';
	
	foreach($message as $ek => $ev){
		$message_string .= $ev.'<br />';
	}
	
	echo '<div id="message" class="update-nag"><p>'
					. __($message_string, 'wp-secure-login')
					. '</p></div>';
}

function wpsl_objectToArray($d){
  if(is_object($d)){
    $d = get_object_vars($d);
  }
  
  if(is_array($d)){
    return array_map(__FUNCTION__, $d); // recursive
  }elseif(is_object($d)){
    return wpsl_objectToArray($d);
  }else{
    return $d;
  }
}

?>
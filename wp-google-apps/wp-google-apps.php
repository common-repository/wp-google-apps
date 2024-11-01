<?php
/**
 * WP Google Apps: Google Apps Authentication for WordPress. 
 * 
 * @package wpgoogleapps
 * @version 1.0
 * @see http://serow.jp/labs/wpgoogleapps/
 * @license GPL http://www.fsf.org/licensing/licenses/gpl.html
 * 
 * Copyright (C) 2008 Kitahara@Serow - http://serow.jp/
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see http://www.gnu.org/licenses/.
 * 
 */

/*
Plugin Name: WP Google Apps
Plugin URI:  http://serow.jp/labs/wpgoogleapps/
Description: WordPress user management via Google Apps.
Version: 1.0
Author: Kitahara@Serow
Author URI: http://serow.jp/
*/

define('WPGOOGLEAPPS_NAME', 'WP Google Apps');
define('WPGOOGLEAPPS_VERSION', '1.0');
define('WPGOOGLEAPPS_URI', 'http://serow.jp/wpgoogleapps/');
define('WPGOOGLEAPPS_SIGNATURE', 'Powered by <a href="'.WPGOOGLEAPPS_URI.'">'.WPGOOGLEAPPS_NAME.'</a> '.WPGOOGLEAPPS_VERSION);
define('WPGOOGLEAPPS_BASE_URI', 'https://mail.google.com/a/');
define('WPGOOGLEAPPS_POP_URI', 'ssl://pop.gmail.com');
define('WPGOOGLEAPPS_POP_PORT', 995);
define('WPGOOGLEAPPS_IMAP_URI', 'ssl://imap.gmail.com');
define('WPGOOGLEAPPS_IMAP_PORT', 993);

/**
 * wp_googleapps_authenticate() - Checks a user's login information via Google Apps
 * @since 1.0
 *
 * @param string $username User's username
 * @param string $password User's password
 * @return true|false Authenticate results.
 */
function wp_googleapps_authenticate($domain, $username, $password) {
	$username = sanitize_user($username);
	$error = new WP_Error();
	
	if ( '' == $domain )
		return new WP_Error('empty_domain', __('<strong>ERROR</strong>: The domain field is empty.'));

	if ( '' == $username )
		return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));

	if ( '' == $password )
		return new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));

	/* Authenticate Via Google Apps : POP3 */
	$ssl = fsockopen(WPGOOGLEAPPS_POP_URI, WPGOOGLEAPPS_POP_PORT, $err, $errdata, 40);
	if ($ssl) {
		$auth = fgets($ssl, 256);
		fputs($ssl, 'USER '.$username.'@'.$domain."\n");
		$auth = fgets($ssl, 256);
		fputs($ssl, 'PASS '.$password."\n");
		$auth = fgets($ssl, 256);
		fclose ($ssl);
		if(preg_match('/OK/',$auth)) {
			return true;
		} else {
			$error->add('wp_googleapps_login_failed', $auth);
		}
	} else {
		return new WP_Error('wp_googleapps_login_failed', __('<strong>ERROR</strong>: No SSL suport in this server.'));
	}

	/* Authenticate Via Google Apps : IMAP */
	$ssl = fsockopen(WPGOOGLEAPPS_IMAP_URI, WPGOOGLEAPPS_IMAP_PORT, $err, $errdata, 40);
	if ($ssl) {
		$auth = fgets($ssl, 256);
		fputs($ssl, '0000 CAPABILITY'."\n");
		$auth = fgets($ssl, 256);
		$auth = fgets($ssl, 256);
		fputs($ssl, '0001 LOGIN '.$username.'@'.$domain.' '.$password."\n");
		$auth = fgets($ssl, 256);
		fclose ($ssl);
		if(preg_match('/Success/',$auth)) {
			return true;
		} else {
			$error->add('wp_googleapps_login_failed', $auth);
		}
	}
	
	return new WP_Error('wp_googleapps_login_failed', __('<strong>ERROR</strong>: Google Apps login error occurred.'));
}

/**
 * wp_googleapps_validatedomain() - domain varidation
 * @since 1.0
 *
 * @param string $domain Google Apps domain
 * @return true|false regex check.
 */
function  wp_googleapps_validatedomain ($domain) {
	return preg_match("/^([a-z0-9][a-z0-9\\.\\-]{0,63}\\.(com|org|net|biz|info|name|net|pro|aero|coop|museum|[a-z]{2,4}))$/", $domain);
}

/**
 * Check Function exists - wp_login, wp_authenticate
 */
if (function_exists('wp_authenticate')) {
	/**
	 * SAFE MODE
	 */
	if (function_exists('add_action')) {
		add_action('admin_menu', 'wp_googleapps_safe_addmenu');
	}
	/**
	 * SAFE MODE FUNCTIONS
	 */
	function wp_googleapps_safe_addmenu() {
		if (function_exists('add_submenu_page')) {
			$hook = add_submenu_page('plugins.php', 'Google Apps '.__(Options), 'Google Apps '.__(Options), 'manage_options', 'wp_googleapps', 'wp_googleapps_safe_menu');
		}
	}
	/**
	 * SAFE MODE MENU
	 */
	function wp_googleapps_safe_menu () {
?>
	<div class="wrap">
		<h2><?php _e(WPGOOGLEAPPS_NAME); ?></h2>
		<h3><?php _e('Configuration plugin'); ?></h3>
		<p>
			<?php _e(WPGOOGLEAPPS_NAME); ?> <?php _e('is now running in safe mode as to not impair the other plugin\'s operations.'); ?>
		</p>
		<p>
			<?php _e('The wp_login and wp_setcookie WordPress <a href="http://codex.wordpress.org/Pluggable_Functions">pluggable functions</a> have already been redefined, and $wp_googleapps_name cannot provide Google Apps authentication without having access to these functions.'); ?>
		</p>
		<p>
			<?php _e('Please disable any WP plugins that deal with authentication in order to use $wp_googleapps_name. Unfortunately, we cannot provide you with more info as to which plugin is in configuration.'); ?>
		</p>
		<p><?php _e(WPGOOGLEAPPS_SIGNATURE); ?></p>
	</div>		
<?php
	}
} else {
	/**
	 * NORMAL MODE
	 */
	if (function_exists('add_action')) {
		add_action('admin_menu', 'wp_googleapps_normal_addmenu');
	}
	/**
	 * NORMAL MODE FUNCTIONS
	 */
	function wp_googleapps_normal_addmenu() {
		if (function_exists('add_submenu_page')) {
			$hook = add_submenu_page('plugins.php', 'Google Apps '.__(Options), 'Google Apps '.__(Options), 'manage_options', 'wp_googleapps', 'wp_googleapps_normal_menu');
		}
	}
	/**
	 * NORMAL MODE MENU
	 */
	function wp_googleapps_normal_menu () {
		global $wp_roles;
		global $wp_googleapps_domain;
		global $wp_googleapps_useronly;
		global $wp_googleapps_role;

		$wp_googleapps_name = WPGOOGLEAPPS_NAME;
		$wp_googleapps_signature = WPGOOGLEAPPS_SIGNATURE;

		if ($_POST) {
			$domain = strip_tags(html_entity_decode(stripslashes($_POST['domain'])), false);
			$useronly = intval($_POST['useronly']) == 1 ? 1 : 0;
			$defaultrole = strip_tags(html_entity_decode(stripslashes($_POST['defaultrole'])), false);
			if (wp_googleapps_validatedomain($domain)) {
				$message = __('Options saved.');
				update_option('wp_googleapps_domain', $domain);
				update_option('wp_googleapps_useronly', $useronly);
				update_option('wp_googleapps_role', $defaultrole);
			} else {
				$message = __('Failed to save options. Enter valid domain name.');
			}
?>
			<div id="message" class="updated fade"><p><strong><?php echo $message;?></strong></p></div>
<?php
		}
		$wp_googleapps_domain = get_option('wp_googleapps_domain');
		$wp_googleapps_useronly = intval(get_option('wp_googleapps_useronly')) == 1 ? 1 : 0;
		$wp_googleapps_role = get_option('wp_googleapps_role');

		if ($wp_googleapps_useronly) {
			$checked_useronly_yes = 'checked="checked" ';
			$checked_useronly_no = '';
		} else {
			$checked_useronly_yes = '';
			$checked_useronly_no = 'checked="checked" ';
		}
?>
	<div class="wrap">
		<h2><?php _e(WPGOOGLEAPPS_NAME); ?></h2>
		<div class="narrow">
			<h3><?php _e('Configuration'); ?></h3>
			<form action="" method="post" id="wpgoogleapps-conf" style="width: 400px; ">
                <p>
					<label for="domain"><strong><?php _e('Google Apps'); ?> <?php _e('domain name'); ?></strong></label><br />
					<input id="domain" name="domain" type="text" size="16" value="<?php echo $wp_googleapps_domain; ?>" />
					<div><?php _e('Enter'); ?> <a href="http://www.google.com/a/"><?php _e('Google Apps'); ?></a> <?php _e('domain name'); ?>.</div>
					<div>ex) example.com</div>
				</p>
                <p>
					<label for="useronly"><strong><?php _e('For only Google Apps users'); ?></strong></label><br />
					<input type="radio" name="useronly" value="1" <?php echo $checked_useronly_yes; ?>/> <?php _e('Yes'); ?> &nbsp;
					<input type="radio" name="useronly" value="0" <?php echo $checked_useronly_no; ?>/> <?php _e('No'); ?>
				</p>
                <p>
					<label for="defaultrole"><strong><?php _e('Default Role'); ?></strong></label><br />
					<select id="defaultrole" name="defaultrole">
<?php wp_dropdown_roles($wp_googleapps_role); ?>
					</select>
				</p>
                <p style="text-align: center;">
				<input type="submit" class="button" value="<?php _e('Update options &raquo;'); ?>" />
				</p>
			</form>
			<p><?php _e(WPGOOGLEAPPS_SIGNATURE); ?></p>
		</div>
	</div>
<?php
	}
	/**
	 * WP's wp_authenticate overwrite.
	 * @since 1.0
	 *
	 * @param string $username User's username
	 * @param string $password User's password
	 * @return WP_Error|WP_User WP_User object if login successful, otherwise WP_Error object.
	 */
	function wp_authenticate($username, $password) {
		$username = sanitize_user($username);

		$enable_wp_googleapps = false;

		$wp_googleapps_domain = get_option('wp_googleapps_domain');
		$wp_googleapps_useronly = intval(get_option('wp_googleapps_useronly')) == 1 ? 1 : 0;
		$wp_googleapps_role = get_option('wp_googleapps_role');

		if ( '' == $username )
			return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));

		if ( '' == $password )
			return new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));

		if (wp_googleapps_validatedomain($wp_googleapps_domain)) {
			$enable_wp_googleapps = true;
		}

		$user = get_userdatabylogin($username);

		if ($enable_wp_googleapps) {
			$wp_googleapps_validuser = wp_googleapps_authenticate ($wp_googleapps_domain, $username, $password);
			if ( !$user || ($user->user_login != $username) ) {
				/**
				 * Haven't WP Account
				 */
				if (!is_wp_error($wp_googleapps_validuser)) {
					/**
					 * Create WP Account
					 */
					include_once(ABSPATH . 'wp-admin/includes/admin.php');
					$user_id = wp_create_user($username, $password, $username.'@'.$wp_googleapps_domain);
					$newuser = new WP_User($user_id);
					$newuser->set_role($wp_googleapps_role);
					return $newuser;
				} else {
					if ($wp_googleapps_useronly) {
						do_action( 'wp_login_failed', $username );
						return new WP_Error('wp_googleapps_login_failed', __('<strong>ERROR</strong>: Google Apps login error occurred.'));
					} else {
						return $wp_googleapps_validuser;
					}
				}
			} else {
				/**
				 * Have WP Account
				 */
				if (!is_wp_error($wp_googleapps_validuser)) {
					/**
					 * Update WP Account(Password)
					 */
					include_once(ABSPATH . 'wp-admin/includes/admin.php');
					wp_set_password($password, $user->ID);
				} else {
					if ($wp_googleapps_useronly) {
						do_action( 'wp_login_failed', $username );
						return new WP_Error('wp_googleapps_login_failed', __('<strong>ERROR</strong>: Google Apps login error occurred.'));
					}
				}
			}
		}
		
		if ( !$user || ($user->user_login != $username) ) {
			do_action( 'wp_login_failed', $username );
			return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.'));
		}

		$user = apply_filters('wp_authenticate_user', $user, $password);
		if ( is_wp_error($user) ) {
			do_action( 'wp_login_failed', $username );
			return $user;
		}

		if ( !wp_check_password($password, $user->user_pass, $user->ID) ) {
			do_action( 'wp_login_failed', $username );
			return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.'));
		}
		
		return new WP_User($user->ID);
	}
}
?>

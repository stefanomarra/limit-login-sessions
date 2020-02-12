<?php
/*
Plugin Name: Limit Login Sessions
Plugin URI: https://www.stefanomarra.com
Description: Limit concurrent sessions
Version: 1.0
Author: Stefano Marra
Author URI: https://www.stefanomarra.com
License: GPL2
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'SM_Limit_Login_Sessions' ) ) :

	class SM_Limit_Login_Sessions {

		const PLUGIN_ID = 'sm-limit-login-sessions';
		const PLUGIN_NAME = 'Limit Login Sessions';
		const NONCE = 'sm_limit_login_sessions_update_action';
		const DEFAULT_MAX_MESSIONS = 5;

		/**
		 * Single instance of the class
		 *
		 * @since 1.0.0
		 */
		protected static $_instance;

		/**
		 * Initialize
		 */
		function __construct() {

			add_filter('authenticate', array( $this, 'check_authenticate' ), 15, 2);
			add_filter('attach_session_information', array( $this, 'attach_session_information' ) );
			add_action('template_redirect', array( $this, 'update_session_last_activity' ) );

			if ( is_admin() ) {
				add_action( 'admin_menu', array( $this, 'register_options_page' ) );
				add_action( 'admin_menu', array( $this, 'digest_post_data' ) );
			}
		}

		/**
		 * Check the user authentication
		 *
		 * @since 1.0.0
		 * @return void
		 */
		public function check_authenticate($user, $username) {

			// 1. Get all active session for this user
			if ( !username_exists($username) || !$user = get_user_by('login', $username) ) {
				return null; // Trigger WP default no username/password matched error
			}

			// Setup vars
			$max_sessions = get_option( 'sm_lls_max_sessions', self::DEFAULT_MAX_MESSIONS );
			// $max_oldest_allowed_session_hours = 4;

			$manager = WP_Session_Tokens::get_instance( $user->ID );
			$sessions =  $manager->get_all();

			// 2. Count all active session
			$session_count = count($sessions);

			// 3. Return okay if active session less then $max_sessions
			if ( $session_count < $max_sessions ) {
				return $user;
			}

			$oldest_session = $this->get_oldest_session($sessions);

			// 4. If active sessions is equal to 5 then check if a session has no activity last 4 hours
			// 5. if oldest session have activity return error
			// if (
			// 	!$oldest_session // if no oldest is found do not allow
			// 	|| ( $oldest_session['last_activity'] + $max_oldest_allowed_session_hours * HOUR_IN_SECONDS ) > time()
			// ) {
			// 	return new WP_Error('max_session_reached', "Maximum $max_sessions login sessions are allowed. Please contact site administrator.");
			// }

			// 5. Oldest activity session doesn't have activity is given recent hours destroy oldest active session and authenticate the user

			$verifier = $this->get_verifier_by_session($oldest_session, $user->ID);

			$this->destroy_session($verifier, $user->ID);

			return $user;
		}

		/**
		 * Gets the oldest session
		 *
		 * @param array $sessions
		 */
		private function get_oldest_session($sessions){
			$sess = false;

			foreach ($sessions as $session) {

				if ( ! isset($session['last_activity']) ) {
					continue;
				}

				if ( ! $sess ) {
					$sess = $session;
					continue;
				}

				if ( $sess['last_activity'] > $session['last_activity'] ) {
					$sess = $session;
				}
			}

			return $sess;
		}

		/**
		 * Get verifier
		 *
		 * @param string $sessions
		 */
		private function get_verifier_by_session($session, $user_id = null){

			if ( !$user_id ) {
				$user_id = get_current_user_id();
			}

			$session_string = implode(',', $session);
			$sessions = get_user_meta( $user_id, 'session_tokens', true );

			if ( empty($sessions) ) {
				return false;
			}

			foreach ($sessions as $verifier => $sess) {
				$sess_string = implode(',', $sess);

				if ( $session_string == $sess_string ) {
					return $verifier;
				}
			}

			return false;
		}

		/**
		 * Destroys a session
		 *
		 * @param  string $verifier
		 * @param  int $user_id
		 * @return bool true if the session has been destroyed
		 */
		private function destroy_session($verifier, $user_id){

			$sessions = get_user_meta( $user_id, 'session_tokens', true );

			if ( !isset($sessions[$verifier]) ) {
				return true;
			}

			unset($sessions[$verifier]);

			if ( !empty($sessions) ) {
				update_user_meta( $user_id, 'session_tokens', $sessions );
				return true;
			}

			delete_user_meta( $user_id, 'session_tokens');
			return true;
		}

		/**
		 * Attaches the time of last activity in session
		 */
		public function attach_session_information($session) {
			$session['last_activity'] = time();
			return $session;
		}

		/**
		 * Attaches the time of last activity in session
		 */
		public function update_session_last_activity($session) {
			if ( ! is_user_logged_in() ) {
				return;
			}

			// get the login cookie from browser
			$logged_in_cookie = $_COOKIE[LOGGED_IN_COOKIE];

			// check for valid auth cookie
			if ( !$cookie_element = wp_parse_auth_cookie($logged_in_cookie) ) {
				return;
			}

			// get the current session
			$manager = WP_Session_Tokens::get_instance( get_current_user_id() );

			$current_session = $manager->get($cookie_element['token']);

			if (
				$current_session['expiration'] <= time() // only update if session is not expired
				|| ( $current_session['last_activity'] + 5 * MINUTE_IN_SECONDS ) > time() // only update in every 5 min to reduce db load
			){
				return;
			}

			$current_session['last_activity'] = time();
			$manager->update($cookie_element['token'], $current_session);
		}

		/**
		 * Register wp option page
		 *
		 * @since 1.0.0
		 * @return void
		 */
		public function register_options_page() {
			add_submenu_page( 'options-general.php', self::PLUGIN_NAME, self::PLUGIN_NAME, 'manage_options', self::PLUGIN_ID, array( $this, 'display_option_page' ) );
		}

		/**
		 * Displays the option page
		 *
		 * @return void
		 */
		public function display_option_page() {
			?>

			<div class="wrap">
				<h2><?php echo self::PLUGIN_NAME; ?></h2>
				<form method="post" action="options-general.php?page=<?php echo self::PLUGIN_ID; ?>" id="options_form" >
					<?php
					echo '<table class="form-table" >';
					echo "<tr>
							<th scope='row'>Max Concurrent Sessions</th>
							<td>
								<input type='text' name='sm_lls_max_sessions' value='" . get_option( 'sm_lls_max_sessions', self::DEFAULT_MAX_MESSIONS ) . "' class='regular-text' style='width: 80px;' />
								<p class='description'>Define the max number of concurrent session a single user can have</p>
							</td>
						</tr>";
					echo "</table>";

					wp_nonce_field( self::NONCE );
					submit_button();
					?>
				</form>
			</div>

			<?php
		}

		/**
		 * Process any plugin admin update
		 * @return void
		 */
		public function digest_post_data() {

			if ( isset( $_POST['sm_lls_max_sessions'] ) ) {

				if( !wp_verify_nonce( $_POST['_wpnonce'], self::NONCE )){
					wp_die( 'Action failed. Please refresh the page and retry.' );
				}

				// Save in DB
				update_option( 'sm_lls_max_sessions' , (int)trim( $_POST['sm_lls_max_sessions'] ) );
			}

		}

		/**
		 * Return class instance
		 *
		 * @static
		 * @return SM_Limit_Login_Sessions
		 */
		public static function instance() {
			if ( is_null( self::$_instance ) ) {
				self::$_instance = new self();
			}
			return self::$_instance;
		}

	}

endif;

function SM_Limit_Login_Sessions() {
	return SM_Limit_Login_Sessions::instance();
}

return SM_Limit_Login_Sessions();
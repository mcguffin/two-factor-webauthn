<?php

use TwoFactorWebauthn\Core;
use TwoFactorWebauthn\Webauthn;
// echo serialize((object) [
// 	'key' => '-----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbXiiRnuhWgfd/Ts1+UvfgU4HNizG
// tPcDY7/sR4Mfl/yVX4bhIPb4Kaa/zGyViLc8BLCrwEQc0zhwrPTxUKSacQ==
// -----END PUBLIC KEY-----
// ',
//  	'id' => 'hB/kM0DOk0dCERRCCJxkso7ZyB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
// 	'rawId' => [226,128,105,131,15,194,232,235,25,217,233,170,112,21,18,86,149,240,240,24,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
// 	'name' => 'FAKED!'
// ]);exit();
/**
 *
 */
class Two_Factor_Webauthn extends Two_Factor_Provider {

	const REGISTER_USERMETA = '_two_factor_webauthn_register';

	const LOGIN_USERMETA = '_two_factor_webauthn_login';

	/** @var TwoFactorWebauthn\Webauthn\Webauthn */
	protected $webauthn;

	/** @var TwoFactorWebauthn\Core\KeyStore */
	protected $key_store;

	/**
	 * Ensures only one instance of this class exists in memory at any one time.
	 *
	 * @return \Two_Factor_FIDO_U2F
	 */
	static function get_instance() {
		static $instance;

		if ( ! isset( $instance ) ) {
			$instance = new self();
		}

		return $instance;
	}

	/**
	 * Class constructor.
	 *
	 * @since 0.1-dev
	 */
	protected function __construct() {
		/*
		$this->webauthn = new TwoFactorWebauthn\Webauthn\Webauthn( $this->get_app_id() );
		/*/
		$this->webauthn = new Davidearl\WebAuthn\WebAuthn( $this->get_app_id() );
		//*/
		$this->key_store = TwoFactorWebauthn\Core\KeyStore::instance();

		$core = TwoFactorWebauthn\Core\Core::instance();

		wp_register_script(
			'webauthn-login',
			plugins_url( 'js/login/two-factor-webauthn.js', dirname( __FILE__ ) ),
			[ 'jquery' ],
			$core->version(),
			true
		);

		wp_register_script(
			'webauthn-admin',
			plugins_url( 'js/admin/two-factor-webauthn.js', dirname( __FILE__ ) ),
			[ 'jquery' ],
			$core->version(),
			true
		);

		wp_register_style(
			'webauthn-admin',
			plugins_url( 'css/admin/two-factor-webauthn.css', dirname( __FILE__ ) ),
			array( ),
			$core->version()
		);

		add_action('wp_ajax_webauthn-register', [ $this, 'ajax_register' ] );
		add_action('wp_ajax_webauthn-delete-key', [ $this, 'ajax_delete_key' ] );
		add_action('wp_ajax_webauthn-test-key', [ $this, 'ajax_test_key' ] );

		add_action( 'two-factor-user-options-' . __CLASS__, array( $this, 'user_options' ) );

		parent::__construct();

	}


	/**
	 * Enqueue assets for login form.
	 *
	 * @since 0.1-dev
	 */
	public function login_enqueue_assets() {
		wp_enqueue_script( 'webauthn-login' );
	}

	/**
	 * Return the U2F AppId. U2F requires the AppID to use HTTPS
	 * and a top-level domain.
	 *
	 * @return string AppID URI
	 */
	public function get_app_id() {
		// we want logins persistent over the network
		if ( is_multisite() ) {
//			return get_network()->domain;
		}

		$url_parts = wp_parse_url( home_url() );

		return $url_parts['host'];

		if ( ! empty( $url_parts['port'] ) ) {
			return sprintf( 'https://%s:%d/', $url_parts['host'], $url_parts['port'] );
		} else {
			return sprintf( 'https://%s/', $url_parts['host'] );
//			return $url_parts['host'];
		}
	}


	/**
	 * Returns the name of the provider.
	 *
	 * @since 0.1-dev
	 */
	public function get_label() {
		return _x( 'WebAuthn', 'Provider Label', 'bsb-two-factor' );
	}

	/**
	 * Prints the form that prompts the user to authenticate.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return null
	 */
	public function authentication_page( $user ) {
		require_once( ABSPATH . '/wp-admin/includes/template.php' );


		// U2F doesn't work without HTTPS.
		if ( ! is_ssl() ) {
			?>
			<p><?php esc_html_e( 'U2F requires an HTTPS connection. Please use an alternative 2nd factor method.', 'two-factor' ); ?></p>
			<?php

			return;
		}

		try {
			$keys = $this->key_store->get_keys( $user->ID );
			$auth_opts = $this->webauthn->prepareForLogin( json_encode( $keys ) );
			update_user_meta( $user->ID, self::LOGIN_USERMETA, $auth_opts );
		} catch ( Exception $e ) {
			?>
			<p><?php esc_html_e( 'An error occurred while creating authentication data.', 'two-factor' ); ?></p>
			<?php
			return null;
		}


		wp_localize_script(
			'webauthn-login',
			'webauthnL10n',
			[
				'action' => 'webauthn-login',
				'payload' => $auth_opts,
				'_wpnonce' => wp_create_nonce('webauthn-login'),
			]
		);

		wp_enqueue_script( 'webauthn-login' );

		?>
		<p><?php esc_html_e( 'Now insert (and tap) your Security Key.', 'two-factor' ); ?></p>
		<input type="hidden" name="webauthn_response" id="webauthn_response" />
		<?php

	}



	/**
	 * Validates the users input token.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function validate_authentication( $user ) {

		$credential = wp_unslash( $_POST['webauthn_response'] );

		$keys = $this->key_store->get_keys( $user->ID );

		return $this->webauthn->authenticate( $credential, json_encode($keys) );

	}


	/**
	 * Whether this Two Factor provider is configured and available for the user specified.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function is_available_for_user( $user ) {
		// only works for currently logged in user
		return true;
		return intval( $user->id ) === intval( get_current_user_id() );
	}





	/**
	 * Inserts markup at the end of the user profile field for this provider.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function user_options( $user ) {

		wp_enqueue_script( 'webauthn-admin' );

		$challenge = $this->webauthn->prepareChallengeForRegistration( $user->display_name, $user->user_login);
		//$this->key_store
		$createData = [
			'action' => 'webauthn-register',
			'payload' => $challenge,
			'_wpnonce' => wp_create_nonce( 'webauthn-register' )
		];


		update_user_meta( $user->ID, self::REGISTER_USERMETA, $challenge );

		$keys = $this->key_store->get_keys( $user->ID );

		?>
		<p>
			<?php esc_html_e( 'Requires an HTTPS connection.', 'two-factor' ); ?>
		</p>
		<button class="button-secondary" id="webauthn-register-key" data-create-options="<?php echo esc_attr( json_encode( $createData ) ) ?>"><?php esc_html_e('Register Key'); ?></button>
		<ul class="keys" id="webauthn-keys">
			<?php
			foreach ( $keys as $key ) {
				echo $this->get_key_item( $key );
			}
			?>
		</ul>
		<?php
	}

	public function ajax_register() {

		check_ajax_referer('webauthn-register');

		$user_id = get_current_user_id();
		//$challenge = get_user_meta( $user_id, self::REGISTER_USERMETA, true );
		$credential = wp_unslash( $_REQUEST['payload'] );

		// decode response
		$cred = json_decode( $credential );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', esc_html( json_last_error_msg() ) ) );
		}

		$keys = $this->key_store->get_keys( $user_id );

		try {
			header('Content-Type: text/plain');
			$keyJSON = $this->webauthn->register( $credential, '' );
			$key = json_decode($keyJSON);
			$this->key_store->save_key( $user_id, $key[0] );
			error_log(var_export($key[0],true));
		} catch( \Exception $err ) {
			throw $err;
		}
		if ( false !== $this->key_store->find_key( $user_id, $pubKey->id ) ) {
			wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Key already Exists', 'two-factor-webauthn' ) ) );
			exit();
		}

		delete_user_meta( $user_id, self::REGISTER_USERMETA );





//
/*
*/
		wp_send_json([
			'success' => true,
			'html' => $this->get_key_item( $pubKey ),//'<div>'.$pubKey->name.'</div>',
			'pubKey' => $pubKey,
		]);

	}

	public function ajax_delete_key() {

		check_ajax_referer('webauthn-delete-key');
		$user_id = get_current_user_id();
		$keyId = wp_unslash( $_REQUEST['payload'] );

		if ( $this->key_store->delete_key( $user_id, $keyId ) ) {
			wp_send_json([
				'success' => true,
			]);
		}

		wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Could not delete key', 'two-factor-webauthn' ) ) );

	}

	public function ajax_test_key() {

		check_ajax_referer('webauthn-test-key');

		$user_id = get_current_user_id();

		$credential = wp_unslash( $_REQUEST['payload'] );

		$keys = $this->key_store->get_keys( $user_id );

		wp_send_json([
			'success' => $this->webauthn->authenticate( $credential, json_encode($keys) ),
		]);

	}

	private function get_key_item( $pubKey ) {
		$keyId = md5( implode( '', array_map( 'chr', $pubKey->id ) ) );
		$out = '<li class="webauthn-key">';
		$out .= sprintf( '<span class="webauthn-key-name">%s</span>', esc_html( $keyId ) );
		$out .= sprintf(
			'<button type="button" class="button webauthn-action-button" data-action="%s">%s</span>',
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-delete-key',
				'payload' => $keyId,
				'_wpnonce' => wp_create_nonce('webauthn-delete-key')
			] ) ),
			esc_html__( 'Delete', 'two-factor-webauthn' )
		);
		$out .= sprintf(
			'<button type="button" class="button webauthn-action-button" data-action="%s">%s</span>',
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-test-key',
				'payload' => $this->webauthn->prepareForLogin( json_encode( [ $pubKey ] ) ),
				'_wpnonce' => wp_create_nonce('webauthn-test-key')
			] ) ),
			esc_html__( 'Test', 'two-factor-webauthn' )
		);
		$out .= '</li>';
		return $out;
	}

}

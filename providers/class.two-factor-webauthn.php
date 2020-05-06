<?php

use TwoFactorWebauthn\Core;
use TwoFactorWebauthn\Webauthn;


/**
 *
 */
class Two_Factor_Webauthn extends Two_Factor_Provider {

	/**
	 * The user meta login key.
	 *
	 * @type string
	 */
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

		$this->webauthn = new Davidearl\WebAuthn\WebAuthn( $this->get_app_id() );

		$this->key_store = TwoFactorWebauthn\Core\KeyStore::instance();

		wp_register_script(
			'webauthn-login',
			plugins_url( 'js/login/two-factor-webauthn.js', dirname( __FILE__ ) ),
			[ 'jquery' ],
			TWO_FACTOR_WEBAUTH_VERSION,
			true
		);

		wp_register_script(
			'webauthn-admin',
			plugins_url( 'js/admin/two-factor-webauthn.js', dirname( __FILE__ ) ),
			[ 'jquery' ],
			TWO_FACTOR_WEBAUTH_VERSION,
			true
		);

		wp_register_style(
			'webauthn-admin',
			plugins_url( 'css/admin/two-factor-webauthn.css', dirname( __FILE__ ) ),
			array( ),
			TWO_FACTOR_WEBAUTH_VERSION
		);

		add_action('wp_ajax_webauthn-register', [ $this, 'ajax_register' ] );
		add_action('wp_ajax_webauthn-edit-key', [ $this, 'ajax_edit_key' ] );
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

		$url_parts = wp_parse_url( home_url() );

		return $url_parts['host'];

		if ( ! empty( $url_parts['port'] ) ) {
			return sprintf( 'https://%s:%d/', $url_parts['host'], $url_parts['port'] );
		} else {
			return sprintf( 'https://%s/', $url_parts['host'] );
		}
	}


	/**
	 * Returns the name of the provider.
	 *
	 * @return string
	 */
	public function get_label() {
		return _x( 'WebAuthn', 'Provider Label', 'bsb-two-factor' );
	}

	/**
	 * Prints the form that prompts the user to authenticate.
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
			$auth_opts = $this->webauthn->prepareAuthenticate( $keys );
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
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function validate_authentication( $user ) {

		$credential = json_decode( wp_unslash( $_POST['webauthn_response'] ) );

		if ( ! is_object( $credential ) ) {
			// json decode error
			error_log( 'credential not object' );
			return false; // failed
		}

		$keys = $this->key_store->get_keys( $user->ID );

		$auth = $this->webauthn->authenticate( $credential, $keys );

		if ( $auth === false ) {
			error_log( 'credential invalid' );
			error_log( $this->webauthn->getLastError() );
			return false;
		}
		$auth->last_used = time();
		$this->key_store->update_key( $user->ID, $auth, $auth->md5id );
		delete_user_meta( $user->ID, self::LOGIN_USERMETA );

		return true;
	}


	/**
	 * Whether this Two Factor provider is configured and available for the user specified.
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function is_available_for_user( $user ) {
		// only works for currently logged in user
		return function_exists('openssl_verify');
	}


	/**
	 * Inserts markup at the end of the user profile field for this provider.
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function user_options( $user ) {

		wp_enqueue_script( 'webauthn-admin' );
		wp_enqueue_style( 'webauthn-admin' );

		$challenge = $this->webauthn->prepareRegister( $user->display_name, $user->user_login );

		$createData = [
			'action' => 'webauthn-register',
			'payload' => $challenge,
			'_wpnonce' => wp_create_nonce( 'webauthn-register' )
		];

		/*  [ (object) [ 'key' => str, 'id' => [ int, int, ...], 'label' => str ], ... ]  */
		$keys = $this->key_store->get_keys( $user->ID );

		?>
		<p>
			<?php esc_html_e( 'Requires an HTTPS connection.', 'two-factor' ); ?>
		</p>
		<button class="button-secondary" id="webauthn-register-key" data-create-options="<?php echo esc_attr( json_encode( $createData ) ) ?>"><?php esc_html_e('Register Key'); ?></button>
		<ul class="keys" id="webauthn-keys">
			<?php
			foreach ( $keys as $key ) {
				echo wp_kses( $this->get_key_item( $key ), [
					'li'	=> [ 'id' => [], 'class' => [], ],
					'span'	=> [ 'id' => [], 'class' => [], 'data-action' => [], 'tabindex' => [] ],
					'a'		=> [ 'id' => [], 'class' => [], 'data-action' => [], 'tabindex' => [], 'href' => [] ],
				] );
			}
			?>
		</ul>
		<?php
	}


	/**
	 *	Registration Ajax Callback
	 */
	public function ajax_register() {

		check_ajax_referer('webauthn-register');

		if ( ! isset( $_REQUEST['payload'] ) ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request', 'two-factor-webauthn' ) ) );
		}

		$user_id = get_current_user_id();

		$credential = json_decode( wp_unslash( $_REQUEST['payload'] ) );

		if ( JSON_ERROR_NONE !== json_last_error() ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', esc_html( json_last_error_msg() ) ) );
		}

		$keys = $this->key_store->get_keys( $user_id );

		try {

			$key = $this->webauthn->register( $credential, '' );

			if ( false === $key ) {
				wp_send_json_error( new WP_Error( 'webauthn', $this->webauthn->getLastError() ) );
			}

			$key->label = __( 'New Key','two-factor-webauthn' );
			$key->md5id = md5( implode( '', array_map( 'chr', $key->id ) ) );
			$key->created = time();
			$key->last_used = false;
			$key->tested = false;

			$this->key_store->save_key( $user_id, $key );

		} catch( \Exception $err ) {
			throw $err;
		}
		if ( false !== $this->key_store->find_key( $user_id, $key->md5id ) ) {
			wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Key already Exists', 'two-factor-webauthn' ) ) );
			exit();
		}

		wp_send_json([
			'success' => true,
			'html' => $this->get_key_item( $key ),//'<div>'.$pubKey->name.'</div>',
			'pubKey' => $pubKey,
		]);
	}

	/**
	 *	Edit Key Ajax Callback
	 */
	public function ajax_edit_key() {

		check_ajax_referer('webauthn-edit-key');

		if ( ! isset( $_REQUEST['payload'] ) ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request', 'two-factor-webauthn' ) ) );
		}

		$user_id = get_current_user_id();

		$payload = wp_unslash( $_REQUEST['payload'] );

		if ( ! isset( $payload['md5id'], $payload['label'] ) ) {
			wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Invalid request', 'two-factor-webauthn' ) ) );
		}
		$new_label = sanitize_text_field( $payload['label'] );

		if ( empty( $new_label ) ) {
			wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Invalid label', 'two-factor-webauthn' ) ) );
		}

		$key = $this->key_store->find_key( $user_id, $payload['md5id'] );
		if ( ! $key ) {
			wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'No such key', 'two-factor-webauthn' ) ) );
		}

		$key->label = $new_label;

		if ( $this->key_store->save_key( $user_id, $key, $payload['md5id'] ) ) {
			wp_send_json([
				'success' => true,
			]);
		}

		wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Could not edit key', 'two-factor-webauthn' ) ) );

	}

	/**
	 *	Delete Key Ajax Callback
	 */
	public function ajax_delete_key() {

		check_ajax_referer('webauthn-delete-key');

		if ( ! isset( $_REQUEST['payload'] ) ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request', 'two-factor-webauthn' ) ) );
		}

		$user_id = get_current_user_id();

		$keyId = wp_unslash( $_REQUEST['payload'] );

		if ( $this->key_store->delete_key( $user_id, $keyId ) ) {
			wp_send_json([
				'success' => true,
			]);
		}

		wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Could not delete key', 'two-factor-webauthn' ) ) );

	}



	/**
	 *	Test Key Ajax Callback
	 */
	public function ajax_test_key() {

		check_ajax_referer('webauthn-test-key');

		if ( ! isset( $_REQUEST['payload'] ) ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request', 'two-factor-webauthn' ) ) );
		}

		$user_id = get_current_user_id();

		$credential = wp_unslash( $_REQUEST['payload'] );

		$keys = $this->key_store->get_keys( $user_id );

		$key = $this->webauthn->authenticate( json_decode( $credential ), $keys );

		if ( $key !== false ) {
			// store key tested state
			$key->tested = true;
			$this->key_store->save_key( $user_id, $key, $key->md5id );
		}

		wp_send_json([
			'success' => $key !== false,
			'message' => $this->webauthn->getLastError(),
		]);

	}


	/**
	 *	@param object $pubKey Public key as generated by $this->webauthn->register()
	 *	@return string key HTML to be displayed in user options
	 */
	private function get_key_item( $pubKey ) {
		$out = '<li class="webauthn-key">';
		$out .= sprintf(
			'<span class="webauthn-label webauthn-action" data-action="%s" tabindex="1">%s</span>',

			esc_attr( wp_json_encode( [
				'action' => 'webauthn-edit-key',
				'payload' => $pubKey->md5id,
				'_wpnonce' => wp_create_nonce('webauthn-edit-key')
			] ) ),

			esc_html( $pubKey->label )
		);
		$out .= sprintf(
			'<a href="#" class="webauthn-action webauthn-action-link" data-action="%s">%s</a>',
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-test-key',
				'payload' => $this->webauthn->prepareAuthenticate( [ $pubKey ] ),
				'_wpnonce' => wp_create_nonce('webauthn-test-key')
			] ) ),
			esc_html__( 'Test', 'two-factor-webauthn' )
		);
		$out .= sprintf(
			'<a href="#" class="webauthn-action webauthn-action-link -delete" data-action="%s">%s</a>',
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-delete-key',
				'payload' => $pubKey->md5id,
				'_wpnonce' => wp_create_nonce('webauthn-delete-key')
			] ) ),
			esc_html__( 'Delete', 'two-factor-webauthn' )
		);
		$out .= '</li>';
		return $out;
	}

}

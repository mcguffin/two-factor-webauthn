<?php

use Davidearl\WebAuthn;
use TwoFactorWebAuthn\Core;


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

	/** @var Davidearl\WebAuthn\Webauthn */
	protected $webauthn;

	/** @var TwoFactorWebAuthn\Core\KeyStore */
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

		$this->webauthn = new WebAuthn\WebAuthn( $this->get_app_id() );

		$this->key_store = Core\KeyStore::instance();

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
			[],
			TWO_FACTOR_WEBAUTH_VERSION
		);

		wp_register_style(
			'webauthn-login',
			plugins_url( 'css/login/two-factor-webauthn.css', dirname( __FILE__ ) ),
			[],
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
		wp_enqueue_style( 'webauthn-login' );
	}

	/**
	 * Return the U2F AppId. WebAuthn requires the AppID
	 * to be the current domain or a suffix of it.
	 *
	 * @return string AppID FQDN
	 */
	public function get_app_id() {

		$fqdn = parse_url( network_site_url(), PHP_URL_HOST );

		/**
		 * Filter the WebAuthn App ID.
		 *
		 * In order for this to work, the App-ID has to be either the current
		 * (sub-)domain or a suffix of it.
		 *
		 * @param string $fqdn Domain name acting as relying party ID
		 */
		return apply_filters( 'two-factor-webauthn-app-id', $fqdn );

	}


	/**
	 * Returns the name of the provider.
	 *
	 * @return string
	 */
	public function get_label() {
		return _x( 'Web Authentication (FIDO2)', 'Provider Label', 'bsb-two-factor' );
	}

	/**
	 * Prints the form that prompts the user to authenticate.
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return null
	 */
	public function authentication_page( $user ) {

		wp_enqueue_style( 'webauthn-login' );

		require_once( ABSPATH . '/wp-admin/includes/template.php' );


		// U2F doesn't work without HTTPS.
		if ( ! is_ssl() ) {
			?>
			<p><?php esc_html_e( 'Web Authentication requires an HTTPS connection. Please use an alternative 2nd factor method.', 'two-factor-webauthn' ); ?></p>
			<?php

			return;
		}

		try {
			$keys = $this->key_store->get_keys( $user->ID );
			$auth_opts = $this->webauthn->prepareAuthenticate( $keys );
			update_user_meta( $user->ID, self::LOGIN_USERMETA, 1 );
		} catch ( Exception $e ) {
			?>
			<p><?php esc_html_e( 'An error occurred while creating authentication data.', 'two-factor-webauthn' ); ?></p>
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
		<p><?php esc_html_e( 'Please authenticate yourself.', 'two-factor-webauthn' ); ?></p>
		<input type="hidden" name="webauthn_response" id="webauthn_response" />

		<div class="webauthn-retry">
			<p>
				<a href="#" class="webauthn-retry-link button-primary">
					<?php esc_html_e('Connect to Authenticator', 'two-factor-webauthn'); ?>
				</a>
			</p>
		</div>
		<div class="webauthn-unsupported">
			<p>
				<span class="dashicons dashicons-warning"></span>
				<?php esc_html_e( 'Your Browser does not support WebAuthn.', 'two-factor-webauthn' ); ?>
				<?php esc_html_e( 'Please use a backup method.', 'two-factor-webauthn' ); ?>
			</p>
		</div>
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
		$this->key_store->save_key( $user->ID, $auth, $auth->md5id );
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
		return function_exists('openssl_verify') && count( $this->key_store->get_keys( $user->ID ) );
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
			'user_id' => $user->ID,
			'_wpnonce' => wp_create_nonce( 'webauthn-register' )
		];

		/*  [ (object) [ 'key' => str, 'id' => [ int, int, ...], 'label' => str ], ... ]  */
		$keys = $this->key_store->get_keys( $user->ID );

		?>
		<p>
			<?php esc_html_e( 'You can configure hardware authenticators like an USB token or your current device with the button below.', 'two-factor-webauthn' ); ?>
		</p>

		<div class="webauthn-supported webauth-register">
			<button class="button-secondary" id="webauthn-register-key" data-create-options="<?php echo esc_attr( json_encode( $createData ) ) ?>">
				<?php esc_html_e( 'Register Device', 'two-factor-webauthn' ); ?>
			</button>
		</div>

		<div class="webauthn-unsupported hidden">
			<p class="description">
				<span class="dashicons dashicons-warning"></span>
				<?php esc_html_e( 'Your Browser does not support WebAuthn.', 'two-factor-webauthn' ); ?>
			</p>
		</div>

		<ul class="keys" id="webauthn-keys">
			<?php
			foreach ( $keys as $key ) {
				echo wp_kses( $this->get_key_item( $key, $user->ID ), [
					'div'		=> [ 'id' => [], 'class' => [], 'tabindex' => [] ],
					'ul'		=> [ 'id' => [], 'class' => [], ],
					'li'		=> [ 'id' => [], 'class' => [], ],
					'strong'	=> [ 'id' => [], 'class' => [], ],
					'small'		=> [ 'id' => [], 'class' => [], ],
					'br'		=> [ 'id' => [], 'class' => [], ],
					'em'		=> [ 'id' => [], 'class' => [], ],
					'span'		=> [ 'id' => [], 'class' => [], 'data-action' => [], 'data-tested' => [], 'tabindex' => [] ],
					'a'			=> [ 'id' => [], 'class' => [], 'data-action' => [], 'tabindex' => [], 'href' => [] ],
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

		$credential = json_decode( wp_unslash( $_REQUEST['payload'] ) );

		if ( JSON_ERROR_NONE !== json_last_error() ) {
			// error couldn't decode
			wp_send_json_error( new WP_Error( 'webauthn', esc_html( json_last_error_msg() ) ) );
		}

		if ( ! is_object( $credential ) ) {
			// contained some junk
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid credential', 'two-factor-webauthn' ) ) );
		}

		// user id
		if ( isset( $_REQUEST['user_id'] ) ) {
			$user_id = intval( wp_unslash( $_REQUEST['user_id'] ) );
		} else {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request data', 'two-factor-webauthn' ) ) );
		}
		// check permissions
		if ( ! current_user_can( 'edit_users' ) && $user_id !== get_current_user_id() ) {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Not allowed to add key', 'two-factor-webauthn' ) ) );
		}

		$keys = $this->key_store->get_keys( $user_id );

		try {
			$key = $this->webauthn->register( $credential, '' );

			if ( false === $key ) {
				wp_send_json_error( new WP_Error( 'webauthn', $this->webauthn->getLastError() ) );
			}
			/* translators: %s webauthn app id (domain) */
			$key->label = sprintf( esc_html__( 'New Device - %s','two-factor-webauthn' ), $this->get_app_id() );
			$key->md5id = md5( implode( '', array_map( 'chr', $key->id ) ) );
			$key->created = time();
			$key->last_used = false;
			$key->tested = false;

			if ( false !== $this->key_store->find_key( $user_id, $key->md5id ) ) {
				wp_send_json_error( new WP_Error( 'webauthn', esc_html__( 'Device already Exists', 'two-factor-webauthn' ) ) );
				exit();
			}

			$this->key_store->save_key( $user_id, $key );

		} catch( \Exception $err ) {
			throw $err;
		}

		wp_send_json([
			'success' => true,
			'html' => $this->get_key_item( $key, $user_id ),//'<div>'.$pubKey->name.'</div>',
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


		$current_user_id = get_current_user_id();

		if ( isset( $_REQUEST[ 'user_id' ] ) ) {
			$user_id = intval( wp_unslash( $_REQUEST[ 'user_id' ] ) );
		} else {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request data', 'two-factor-webauthn' ) ) );
		}
		// not permitted
		if ( ! current_user_can( 'edit_users' ) && $user_id !== $current_user_id ) {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Operation not permitted', 'two-factor-webauthn' ) ) );
		}

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

		$key_id = wp_unslash( $_REQUEST['payload'] );

		$current_user_id = get_current_user_id();

		if ( isset( $_REQUEST[ 'user_id' ] ) ) {
			$user_id = intval( wp_unslash( $_REQUEST[ 'user_id' ] ) );
		} else {
			$user_id = $current_user_id;
		}
		// not permitted
		if ( ! current_user_can( 'edit_users' ) && $user_id !== $current_user_id ) {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Operation not permitted', 'two-factor-webauthn' ) ) );
		}

		if ( $this->key_store->delete_key( $user_id, $key_id ) ) {
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

		$credential = wp_unslash( $_REQUEST['payload'] );

		$current_user_id = get_current_user_id();

		if ( isset( $_REQUEST[ 'user_id' ] ) ) {
			$user_id = intval( wp_unslash( $_REQUEST[ 'user_id' ] ) );
		} else {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Invalid request data', 'two-factor-webauthn' ) ) );
		}
		// not permitted
		if ( ! current_user_can( 'edit_users' ) && $user_id !== $current_user_id ) {
			wp_send_json_error( new WP_Error( 'webauthn', __( 'Operation not permitted', 'two-factor-webauthn' ) ) );
		}


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
	private function get_key_item( $pubKey, $user_id ) {

		$out = '<li class="webauthn-key">';

		// info
		$out .= sprintf(
			'<span class="webauthn-label webauthn-action" data-action="%1$s" tabindex="1">%2$s</span>',

			esc_attr( wp_json_encode( [
				'action' => 'webauthn-edit-key',
				'payload' => $pubKey->md5id,
				'user_id' => $user_id,
				'_wpnonce' => wp_create_nonce('webauthn-edit-key')
			] ) ),

			esc_html( $pubKey->label )
		);
		$date_format = _x( 'm/d/Y', 'Short date format', 'two-factor-webauthn' );
		$out .= sprintf(
			'<span class="webauthn-created"><small>%s</small><br />%s</span>',
			__( 'Created:', 'two-factor-webauthn' ),
			date_i18n( $date_format, $pubKey->created )
		);
		$out .= sprintf(
			'<span class="webauthn-used"><small>%s</small><br />%s</span>',
			__( 'Last used:', 'two-factor-webauthn' ),
			$pubKey->last_used ? date_i18n( $date_format, $pubKey->last_used ) : esc_html__('- Never -','two-factor-webauthn')
		);

		// actions
		$out .= sprintf(
			'<a href="#" class="webauthn-action webauthn-action-link -test webauthn-supported" title="%1$s" data-action="%2$s" >
				%1$s
				<span class="dashicons dashicons-yes-alt" data-tested="%3$s"></span>
			</a>',
			esc_html__( 'Test', 'two-factor-webauthn' ),
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-test-key',
				'payload' => $this->webauthn->prepareAuthenticate( [ $pubKey ] ),
				'user_id' => $user_id,
				'_wpnonce' => wp_create_nonce('webauthn-test-key')
			] ) ),
			$pubKey->tested ? 'tested' : 'untested'
		);
		$out .= sprintf(
			'<a href="#" class="webauthn-action webauthn-action-link -delete" title="%1$s" data-action="%2$s">
				<span class="dashicons dashicons-trash"></span>
				<span class="screen-reader-text">%1$s</span>
			</a>',
			esc_html__( 'Delete', 'two-factor-webauthn' ),
			esc_attr( wp_json_encode( [
				'action' => 'webauthn-delete-key',
				'payload' => $pubKey->md5id,
				'user_id' => $user_id,
				'_wpnonce' => wp_create_nonce('webauthn-delete-key')
			] ) )
		);
		$out .= '</li>';

		// $out .= ;
		// $out .= date_i18n( get_option( 'date_format', 'r' ), $pubKey->last_used );
		return $out;
	}

}

<?php
/**
 *	@package TwoFactorWebauthn\Core
 *	@version 1.0.1
 *	2018-09-22
 */

namespace TwoFactorWebauthn\Core;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}
use TwoFactorWebauthn\Asset;
use TwoFactorWebauthn\Compat;

class Core extends Plugin implements CoreInterface {

	/**
	 *	@inheritdoc
	 */
	protected function __construct() {

		add_action( 'plugins_loaded' , array( $this , 'init_compat' ), 0 );
		add_action( 'init' , array( $this , 'init' ) );

		add_action( 'wp_enqueue_scripts' , array( $this , 'enqueue_assets' ) );

		$args = func_get_args();
		parent::__construct( ...$args );
	}

	/**
	 *	Load frontend styles and scripts
	 *
	 *	@action wp_enqueue_scripts
	 */
	public function enqueue_assets() {
	}


	/**
	 *	Load Compatibility classes
	 *
	 *  @action plugins_loaded
	 */
	public function init_compat() {

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
		    require_once( ABSPATH . '/wp-admin/includes/plugin.php' );
		}
		if ( is_plugin_active( 'two-factor/two-factor.php' ) ) {
			Compat\TwoFactor::instance();
			// Two_Factor_Provider
		}
	}




	/**
	 *	Init hook.
	 *
	 *  @action init
	 */
	public function init() {
	}


}

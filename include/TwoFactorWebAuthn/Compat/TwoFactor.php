<?php
/**
 *	@package TwoFactorWebauthn\Compat
 *	@version 1.0.0
 *	2018-09-22
 */

namespace TwoFactorWebauthn\Compat;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

use TwoFactorWebauthn\Core;


class TwoFactor extends Core\Singleton implements Core\ComponentInterface {

	/**
	 *	@inheritdoc
	 */
	protected function __construct() {

		add_filter('two_factor_providers', [ $this, 'providers' ] );

	}

	/**
	 *	Remove Dummy provider
	 *
	 *	@filter two_factor_providers
	 */
	public function providers( $providers ) {
		$core = Core\Core::instance();

		$providers['Two_Factor_Webauthn'] = $core->get_plugin_dir() . '/providers/class.two-factor-webauthn.php'; // the fucken path...

		return $providers;
	}

	/**
	 *	@inheritdoc
	 */
	public function activate(){

	}

	/**
	 *	@inheritdoc
	 */
	public function deactivate(){

	}

	/**
	 *	@inheritdoc
	 */
	public static function uninstall() {
		// remove content and settings
	}

	/**
 	 *	@inheritdoc
	 */
	public function upgrade( $new_version, $old_version ) {

	}

}

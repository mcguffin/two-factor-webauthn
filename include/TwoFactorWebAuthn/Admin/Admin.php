<?php
/**
 *	@package TwoFactorWebauthn\Admin
 *	@version 1.0.0
 *	2018-09-22
 */

namespace TwoFactorWebauthn\Admin;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

use TwoFactorWebauthn\Asset;
use TwoFactorWebauthn\Core;


class Admin extends Core\Singleton {

	private $core;

	/**
	 *	@inheritdoc
	 */
	protected function __construct() {

		$this->core = Core\Core::instance();

		add_action( 'admin_init', array( $this , 'admin_init' ) );
		add_action( 'admin_print_scripts', array( $this , 'enqueue_assets' ) );
	}


	/**
	 *	Admin init
	 *	@action admin_init
	 */
	public function admin_init() {
	}

	/**
	 *	Enqueue options Assets
	 *	@action admin_print_scripts
	 */
	public function enqueue_assets() {
		Asset\Asset::get('css/admin/main.css')->enqueue();

		Asset\Asset::get('js/admin.js')
			->deps( array( 'jquery' ) )
			->localize( array(
				/* Script Localization */
			) )
			->enqueue();
	}

}

<?php
/**
 *	@package TwoFactorWebAuthn
 *	@version 1.0.0
 *	2018-09-22
 */

namespace TwoFactorWebAuthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}


function __autoload( $class ) {

	if ( false === ( $pos = strpos( $class, '\\' ) ) ) {
		return;
	}

	$ds = DIRECTORY_SEPARATOR;
	$top = substr( $class, 0, $pos );

	if ( false === is_dir( dirname( __FILE__ ) .$ds . $top ) ) {
		// not our plugin.
		return;
	}

	$file = dirname( __FILE__ ) . $ds . str_replace( '\\', $ds, $class ) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	} else {
		throw new \Exception( sprintf( 'Class `%s` could not be loaded. File `%s` not found.', $class, $file ) );
	}
}


spl_autoload_register( 'TwoFactorWebAuthn\__autoload' );

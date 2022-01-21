<?php


if ( ! defined('ABSPATH') ) {
	die('Nope');
}

use phpseclib\Crypt\RSA;
use CBOR\Types\CBORByteString;

function two_factor_webauthn_log_in( $what ) {
	if ( is_array( $what ) ) {
		foreach ( $what as $i => $el ) {
			if ( $el instanceOf CBORByteString ) {
				/*
				$what[$i] = base64_encode( $el->get_byte_string() );
				/*/
				$what[$i] = bin2hex( $el->get_byte_string() );
				//*/
			}
		}
	}

	if ( ! is_scalar( $what ) ) {
		$what = var_export($what,true);
	}
	error_log('Current Action: '.current_action());
	error_log($what);
}

function two_factor_webauthn_log_out( $what ) {
	if ( $what instanceOf phpseclib\Crypt\RSA ) {
		$what = $what->getPublicKey();
	}
	$pubkey = $what;
	$what = preg_replace('/^--(.+)--$/','',$what );
	$what = preg_replace('/\r\n/','',$what );
	$what = bin2hex( base64_decode( $what ) );
	error_log('Current Action: '.current_action());
	error_log($what);
	error_log($pubkey);
}

add_action( 'webauthn_register_key_ecdsa', 'two_factor_webauthn_log_out' );
add_action( 'webauthn_registered_key_ecdsa', 'two_factor_webauthn_log_out' );
add_action( 'webauthn_register_key_rsa', 'two_factor_webauthn_log_in' );
add_action( 'webauthn_registered_key_rsa', 'two_factor_webauthn_log_out' );

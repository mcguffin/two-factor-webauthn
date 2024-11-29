<?php

/*
Plugin Name: Two Factor Web Authentication
Plugin URI: https://github.com/mcguffin/two-factor-webauthn
Description: Web Authentication for the Two Factor WordPress Plugin
Author: Jörn Lund
Version: 0.1.5
Author URI: https://github.com/mcguffin
GitHub Plugin URI: mcguffin/two-factor-webauthn
License: GPL3
Requires WP: 4.8
Requires PHP: 5.6
Text Domain: two-factor-webauthn
Domain Path: /languages/
Update URI: https://github.com/mcguffin/two-factor-webauthn/raw/master/.wp-release-info.json
*/

/*  Copyright 2020 joern

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*
Plugin was generated with Jörn Lund's WP Skelton
https://github.com/mcguffin/wp-skeleton
*/

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

define( 'TWO_FACTOR_WEBAUTH_VERSION', include dirname( __FILE__ ).'/include/version.php' );

require_once __DIR__ . DIRECTORY_SEPARATOR . 'include/autoload.php';

add_filter('two_factor_providers', function( $providers ) {

	$providers['Two_Factor_Webauthn'] = dirname( __FILE__ ) . '/providers/class.two-factor-webauthn.php';

	return $providers;

} );


add_action('plugins_loaded', function() {
	load_plugin_textdomain( 'two-factor-webauthn', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
});


// Enable WP auto update
add_filter( 'update_plugins_github.com', function( $update, $plugin_data, $plugin_file, $locales ) {

	if ( ! preg_match( "@{$plugin_file}$@", __FILE__ ) ) { // not our plugin
		return $update;
	}

	$response = wp_remote_get( $plugin_data['UpdateURI'] );

	if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) > 200 ) { // response error
		return $update;
	}

	return json_decode( wp_remote_retrieve_body( $response ), true, 512 );
}, 10, 4 );

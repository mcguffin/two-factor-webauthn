<?php

namespace TwoFactorWebauthn\Core;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}


class KeyStore extends Singleton {

	const PUBKEY_USERMETA_KEY = '_two_factor_webauthn_pubkey';

	public function get_keys( $user_id ) {
		return get_user_meta( $user_id, self::PUBKEY_USERMETA_KEY );
	}

	public function find_key( $user_id, $keyLike = null ) {
		global $wpdb;
		if ( is_null( $keyLike ) ) {
			return false;
		}
		$sql = $wpdb->prepare(
			"SELECT * FROM $wpdb->usermeta WHERE user_id=%d AND meta_key=%s AND meta_value LIKE %s",
			$user_id,
			self::PUBKEY_USERMETA_KEY,
			'%' . $keyLike . '%'
		);
		$found = $wpdb->get_results( $sql );
		foreach ( $found as $key ) {
			return maybe_unserialize( $key->meta_value );
		}
		return false;

	}

	private function create_key( $user_id, $key ) {
		return add_user_meta( $user_id, self::PUBKEY_USERMETA_KEY, $key );
	}

	public function save_key( $user_id, $key, $keyLike = null ) {
		$oldKey = $this->find_key( $user_id, $keyLike );
		if ( false === $oldKey ) {
			return $this->create_key( $user_id, $key );
		}
		return update_user_meta( $user_id, self::PUBKEY_USERMETA_KEY, $key, $oldKey );
	}

	public function delete_key( $user_id, $keyLike ) {
		global $wpdb;
		$sql = $wpdb->prepare(
			"DELETE FROM $wpdb->usermeta WHERE user_id=%d AND meta_key=%s AND meta_value LIKE %s",
			$user_id,
			self::PUBKEY_USERMETA_KEY,
			'%' . $keyLike . '%'
		);
		return $wpdb->query( $sql ) !== 0;
	}


}

<?php

namespace TwoFactorWebauthn\Webauthn;

/**
 *	member of AuthenticatorAttestationResponse (sign up)
 */
class AttestationObject extends Struct {
	private $_rawAuthData;
	public AuthenticatorData $authData; // same as AuthenticatorAssertionResponse::authenticatorData
	public string $fmt = '';
	public array $attStmt = []; // whatever..

	public function __construct() {
		$this->authData = new AuthenticatorData();
	}

	public function set( $prop, $value ) {

		if ( 'authData' === $prop ) {
			if ( is_array( $value ) ) {
				$this->authData = AuthenticatorData::fromCBOR( $value );
			} else if ( $value instanceof AuthenticatorData ) {
				$this->authData = $value;
			} else if ( $value instanceof \CBOR\Types\CBORByteString ) {
				$this->authData = AuthenticatorData::fromCBOR( $value->get_byte_string() );
				// try {
				//
				// } catch (\Exception $err) {
				// 	$this->_rawAuthData = $value->get_byte_string();
				// }
			} else if ( is_object( $value ) ) {
				$this->authData = AuthenticatorData::fromPlainObject( $value );
			} else {
				throw new \Exception( "bad value for {$prop}" );
			}
			return;
		}
		return parent::set( $prop, $value );
	}
}

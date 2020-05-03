<?php

namespace TwoFactorWebauthn\Webauthn;

/**
 *	the return value of navigator.credentials.get()
 */
class AuthenticatorAssertionResponse extends AuthenticatorResponse {

	private array $_rawAuthenticatorData; // CBOR encoded authenticatorData
	public AuthenticatorData $authenticatorData;
	public array $signature;
	public array $userHandle;

	/**
	 *	@param object $rp
	 */
	public function __construct() {

		$this->authenticatorData = new AuthenticatorData();

	}

	public function set( $prop, $value ) {

		if ( 'authenticatorData' === $prop ) {
			if ( is_array( $value ) ) {
				$this->_rawAuthenticatorData = $value;
				$this->authenticatorData = AuthenticatorData::fromCBOR( $value );
			} else if ( $value instanceof AuthenticatorData ) {
				$this->authenticatorData = $value;
			} else if ( is_object( $value ) ) {
				$this->authenticatorData = AuthenticatorData::fromPlainObject( $value );
			} else {
				throw new \Exception( "bad value for authenticatorData" );
			}
			return;
		}
		return parent::set( $prop, $value );
	}

}

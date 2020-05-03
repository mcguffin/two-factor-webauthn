<?php

namespace TwoFactorWebauthn\Webauthn;

/**
 *
 */
class AuthenticatorAttestationResponse extends AuthenticatorResponse {

	private array $_rawAttestationObject;

	public AttestationObject $attestationObject;


	/**
	 *	@param object $rp
	 */
	public function __construct() {

		$this->attestationObject = new AttestationObject();

	}

	public function set( $prop, $value ) {

		if ( 'attestationObject' === $prop ) {
			if ( is_array( $value ) ) {
				$this->_rawAttestationObject = $value;
				$this->attestationObject = AttestationObject::fromCBOR( $value );
			} else if ( $value instanceof AttestationObject ) {
				$this->attestationObject = $value;
			} else if ( is_object( $value ) ) {
				$this->authenticatorData = AttestationObject::fromPlainObject( $value );
			} else {
				throw new \Exception( "bad value for attestationObject" );
			}
			return;
		}
		return parent::set( $prop, $value );
	}

}

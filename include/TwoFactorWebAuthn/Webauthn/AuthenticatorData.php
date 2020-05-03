<?php

namespace TwoFactorWebauthn\Webauthn;

/**
 *	member of AuthenticatorAssertionResponse (login)
 */
class AuthenticatorData extends Struct {

	public string $rpIdHash = '';
	public int $flags = 0;
	public string $signCount = '';
	public AttestedCredentialData $attestedCredentialData;
	public object $extensions;


	public function __construct() {
		$this->attestedCredentialData = new AttestedCredentialData();
		$this->extensions = (object) [];
	}

	/**
	 *	Pseudo-CBOR-Decode
	 */
	public static function fromCBOR( $cbor ) {
		$inst = new self();
		$inst->set( 'rpIdHash', substr( $cbor, 0, 32) );
		$inst->set( 'flags', ord( substr( $cbor, 32, 1) ) );
		$inst->set( 'signCount', substr( $cbor, 33, 4) );
		$inst->attestedCredentialData->set( 'aaguid', substr( $cbor, 37, 16 ) );
		$inst->attestedCredentialData->set( 'credentialIdLength', ( ord( $cbor[53] ) << 8 ) + ord( $cbor[54] ) );
		$inst->attestedCredentialData->set( 'credentialId', substr($cbor, 55, $inst->attestedCredentialData->credentialIdLength)  );
		$cborPubKey  = substr( $cbor, 55 + $inst->attestedCredentialData->credentialIdLength ); // after credId to end of string
        $inst->attestedCredentialData->credentialPublicKey = \CBOR\CBOREncoder::decode( $cborPubKey ); //
		return $inst;
	}

}

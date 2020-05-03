<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class Webauthn {

	protected $rp;

	/**
	 *	@param string $rpId must be a FQDN
	 */
	public function __construct( string $rpId, string $rpName = '' ) {

		$this->rp = new RelyingParty();
		$this->rp->id = $rpId;
		$this->rp->name = empty( $rpName ) ? $rpId : $rpName;

	}

	/**
	 *	Pass return value to navigator.credentials.create()
	 *
	 *	@param object $user
	 *	@return PublicKeyCredentialCreationOptions
	 */
	public function getCreateOptions( object $user, array $excludeCredentials = [] ) {

		$opts = new PublicKeyCredentialCreationOptions();

		$opts->rp = $this->rp;
		$opts->challenge = $this->createChallenge();
		$opts->user = User::fromPlainObject( $user );

		if ( ! $opts->user->id ) {
			$opts->user->generateId( $this->rp );
		}

		return $opts->toPlainObject();

	}


	/**
	 *	@return
	 */
	public function create( object $publicKeyCredential ) {

		// parse input
		$credential = PublicKeyCredential::fromPlainObject( $publicKeyCredential );
		$ao = $credential->response->attestationObject;
		if ( ! in_array( $ao->fmt, [ 'none', 'packed' ] ) ) {
			throw new \Exception('fmt is neither `none` nor `packed`');
		}
		if ( ! $ao->authData->rpIdHash ) {
			throw new \Exception('no auth data');
		}
		$rpIdHash = hash('sha256', $this->rp->id, true);

		if ( $rpIdHash !== $ao->authData->rpIdHash ) {
			throw new \Exception('rp hash didnt verify');
		}
		// do all checks
		if ( ! ( $ao->authData->flags & 0x41 ) ) {
			// @see https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
			// require bit 0 & bit 6 being set
			throw new \Exception('flags not set');
		}

		$credId = implode( '', array_map( 'chr', $credential->rawId ) );
		if ( $credId !== $ao->authData->attestedCredentialData->credentialId ) {
			throw new \Exception('IDs dont match');
		}
		$pubKey = $ao->authData->attestedCredentialData->getPublicKey( $credential->rawId );
		return $pubKey->toPlainObject();

	}


	/**
	 *	Pass return value to navigator.credentials.sign()
	 *
	 *	@param object $pubKey
	 *	@param string $user
	 *	@return PublicKeyCredentialCreationOptions
	 */
 	public function getAuthenticateOptions( $pubkeys = [] ) {

		$opts = new PublicKeyCredentialRequestOptions();

		$opts->rpId = $this->rp->id;//implode( '', array_map( 'chr', $this->rp->id ) );
		$opts->challenge = $this->createChallenge();
		$opts->userVerification = 'discouraged';

		// allow only for specific key(s)
		foreach ( (array) $pubkeys as $pubkey ) {
			$opts->allowCredentails[] = (object) [
				'type' => 'public-key',
				'id' => $pubkey->rawId, // array_map( 'ord', str_split( base64_decode( $pubkey->id ) ) )
				'transports' => [ 'usb', 'nfc', 'ble', 'internal' ] // allow all
			];
		}

		return $opts->toPlainObject();

	}


	public function authenticate(/* array $options */ ) {
		// do the create thing
	}


	private function createChallenge( int $length = 16 ) : array {
		if ( function_exists( 'random_bytes' ) ) {
			$str = random_bytes( $length );
		} else if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
			$str = openssl_random_pseudo_bytes( $length, $crypto_strong );
			if ( ! $crypto_strong ) {
				throw new \Exception("openssl_random_pseudo_bytes did not return a cryptographically strong result", 1);
			}
			return $bytes;
		} else {
			throw new \Exception("Neither random_bytes not openssl_random_pseudo_bytes exists. PHP too old? openssl PHP extension not installed?", 1);
		}
		return array_map( 'ord', str_split( $str ) );
	}

}

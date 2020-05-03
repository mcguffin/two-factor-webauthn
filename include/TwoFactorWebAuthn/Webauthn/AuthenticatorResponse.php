<?php

namespace TwoFactorWebauthn\Webauthn;

class AuthenticatorResponse extends Struct {

	public string $clientDataJSON = 'null';


	public function __get( $prop ) {
		if ( 'clientData' === $prop ) {
			return json_decode( $this->clientDataJSON );
		}
		throw new \Exception( "Property $prop does not exist" );
	}

}

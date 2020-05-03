<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class PublicKeyCredential extends Struct {
	public string $type = '';
	public string $id = '';
	public array $rawId = [];
	public AuthenticatorAttestationResponse $response;

	public function __construct() {
		$this->response = new AuthenticatorAttestationResponse();
	}

}

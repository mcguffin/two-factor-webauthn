<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class PublicKeyCredentialRequestOptions extends Struct {

	public array $challenge = [];
	public int $timeout = 60000;
	public string $rpId = '';
	public array $allowCredentails = [];
	public string $userVerification = ''; // required | preferred | discouraged
	public object $extensions;

	public function __construct() {
		$this->extensions = (object) [ 'txAuthSimple' => "Execute order 66" ];
	}

}

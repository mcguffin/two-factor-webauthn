<?php

/*
@see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
*/

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class PublicKeyCredentialCreationOptions extends Struct {
	public RelyingParty $rp;
	public User $user;
	public array $challenge = [];
	public array $pubKeyCredParams = [];
	public int $timeout = 60000;
	public array $excludeCredentials = [];
	public ?AuthenticatorSelection $authenticatorSelection;
	public string $attestation = 'none'; // none | indirect | direct
	public object $extensions;

	public function __construct() {
		$this->rp = new RelyingParty();
		$this->user = new User();
		$this->pubKeyCredParams = [
			new PubKeyCredParams('public-key', -7 ),
		//	new PubKeyCredParams('public-key', -257 ),  // Windows Hello support
		];
		$this->authenticatorSelection = new AuthenticatorSelection();
		$this->extensions = (object) [];

	}
}

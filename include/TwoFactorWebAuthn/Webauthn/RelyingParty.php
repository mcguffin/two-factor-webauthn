<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class RelyingParty extends Struct {

	public string $id = '';
	public string $name = '';
	public ?string $icon;


}

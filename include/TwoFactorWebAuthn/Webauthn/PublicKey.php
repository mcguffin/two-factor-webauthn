<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class PublicKey extends Struct {

	public string $key = '';
	public string $id = '';
	public array $rawId = [];



}

<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class User extends Struct {
	public $icon = null;
	public array $id = [];
	public string $name = '';
	public string $displayName = '';

	public function generateId( RelyingParty $rp ) {
		$idStr = sprintf( '%s--%s--%d', $rp->id, $this->name, time() );
		$this->id = array_map( 'ord', str_split( $idStr ) );
	}
}

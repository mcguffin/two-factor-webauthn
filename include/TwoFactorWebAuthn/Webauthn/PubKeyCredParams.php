<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

class PubKeyCredParams extends Struct {

	public $type = 'public-key';

	/** @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms */
	public $alg = -7; //

	public function __construct( $type = 'public-key', $alg = -7 ) {
		$this->type = $type;
		$this->alg = $alg;
	}


}

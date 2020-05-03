<?php

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}

/**
 *	member of AuthenticatorData
 */
class AttestedCredentialData extends Struct {
	public string $aaguid = '';
	public int $credentialIdLength = 0;
	public string $credentialId = '';
	public array $credentialPublicKey = [];

	public function getPublicKey( array $id ) {
		$pubKey = new PublicKey();
		$pubKey->rawId = $id; //array_map( 'ord', str_split(  ) );
		$pubKey->id = base64_encode( implode( '', array_map( 'chr', $id ) ) );
		$pubKey->key = $this->coseToPem( $this->credentialPublicKey );
		return $pubKey;
	}

	private function coseToPem( array $cosePubKey ) {
		if ( ! isset( $cosePubKey[3] ) ) {
			throw new \Exception('Cannot decode key');
		}
		if ( -7 === $cosePubKey[3] ) { // ES256

			if ( ! isset( $cosePubKey[-2] ) || ! isset( $cosePubKey[-3] ) ) {
				throw new \Exception('Cannot decode key');
			}

			$x = $cosePubKey[-2]->get_byte_string();
            $y = $cosePubKey[-3]->get_byte_string();

			if ( strlen($x) !== 32 || strlen($y) !== 32 ) {
				throw new \Exception('Cannot decode key');
			}
			$der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
	        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
	        $der .= "\x00\x04{$x}{$y}";
	        $pem  = "-----BEGIN PUBLIC KEY-----\x0A";
	        $pem .= chunk_split( base64_encode($der), 64, "\x0A");
	        $pem .= "-----END PUBLIC KEY-----\x0A";
			return $pem;
		} else {
			throw new \Exception('Not implemented yet');
		}
	}
}

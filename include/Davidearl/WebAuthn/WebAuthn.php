<?php

/**
 *	Stolen from https://github.com/davidearl/webauthn
 */
namespace Davidearl\WebAuthn;

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

/**
* @package davidearl\webauthn
*
*
* A class to help manage keys via the webauthn protocol.
*
* Webauthn allows for browser logins using a physical key (such as a
* Yubikey 2) or, in due course, biometrics such as fingerprints, that
* support the protocol.
*
* This is based on the Javascript example at
* https://webauthn.bin.coffee/, but offers a PHP server side.
*
* You need to store a webauthn string (which does not need to be
* indexed) in user records in your database, the value of which is
* consulted and amended by the various functions in this class.
*
* Errors are thrown as simple Exception, with code 0 for user errors (such as validation failure) or 1 for
* programming errors (wrong argument types etc)
*
* Dependencies
* ------------
*
* - You will need to include https://github.com/2tvenom/CBOREncode
* - openssl that supports SHA256
*/

class WebAuthn
{

	private $last_call = null;
	private $last_error = [
		'authenticate' => false,
		'prepareAuthenticate' => false,
		'register' => false,
		'prepareRegister' => false,
	];

    const ES256 = -7;
    const RS256 = -257; // Windows Hello support
    /**
    * construct object on which to operate
    *
    * @param string $appid a string identifying your app, typically the domain of your website which people
    *                      are using the key to log in to. If you have the URL (ie including the
    *                      https:// on the front) to hand, give that;
    *                      if it's not https, well what are you doing using this code?
    */
    public function __construct($appid)
    {
        if (! is_string($appid)) {
            $this->oops('appid must be a string');
        }
        $this->appid = $appid;
        if (strpos($this->appid, 'https://') === 0) {
            $this->appid = substr($this->appid, 8); /* drop the https:// */
        }
    }

	public function getLastError( string $realm = NULL ) {
		if ( is_null( $realm ) ) {
			$realm = $this->last_call;
		}
		if ( is_null( $realm ) ) {
			return false;
		}
		if ( ! isset( $this->last_error[ $realm ] ) ) {
			return false;
		}
		return $this->last_error[ $realm ];
	}

    /**
    * generate a challenge ready for registering a hardware key, fingerprint or whatever:
    * @param $username string by which the user is known potentially displayed on the hardware key
    * @param $userid string by which the user can be uniquely identified. Don't use email address as this can change,
    *                user perhaps the database record id
    * @param $crossPlatform bool default=FALSE, whether to link the identity to the key (TRUE, so it
    *               can be used cross-platofrm, on different computers) or the platform (FALSE, only on
    *               this computer, but with any available authentication device, e.g. known to Windows Hello)
    * @return string pass this JSON string back to the browser
    */
  public function prepareRegister($username, $userid, $crossPlatform = FALSE)
    {
        $result = (object) [];
        $rbchallenge = self::randomBytes(16);
        $result->challenge = self::stringToArray($rbchallenge);
        $result->user = (object) [];
        $result->user->name = $result->user->displayName = $username;
        $result->user->id = self::stringToArray($userid);

        $result->rp = (object) [];
        $result->rp->name = $result->rp->id = $this->appid;

        $result->pubKeyCredParams = [
            [
                'alg' => self::ES256,
                'type' => 'public-key'
            ],
            [
                'alg' => self::RS256,
                'type' => 'public-key'
            ]
        ];

        $result->authenticatorSelection = (object) [];
        if ( $crossPlatform ) {
			$result->authenticatorSelection->authenticatorAttachment = 'cross-platform';
		}

        $result->authenticatorSelection->requireResidentKey = false;
        $result->authenticatorSelection->userVerification = 'discouraged';

        $result->attestation = null;
        $result->timeout = 60000;
        $result->excludeCredentials = []; // No excludeList
        $result->extensions = (object) [];
        $result->extensions->exts = true;

        return [
			'publicKey' => $result,
        	'b64challenge' => rtrim(strtr(base64_encode($rbchallenge), '+/', '-_'), '=')
		];
    }

    /**
    * registers a new key for a user
    * requires info from the hardware via javascript given below
    * @param object $info supplied to the PHP script via a POST, constructed by the Javascript given below, ultimately
    *        provided by the key
    * @param string $userwebauthn the exisitng webauthn field for the user from your
    *        database (it's actaully a JSON string, but that's entirely internal to
    *        this code)
    * @return boolean|object user key
    */
    public function register( object $info ) {

		$this->last_call = __FUNCTION__;

		$this->last_error[ $this->last_call ] = false;

		// check info
		if ( false === $this->validateRegisterInfo( $info ) ) {
			// error generated in validateRegisterInfo()
			return false;
		}

        /* check response from key and store as new identity. This is a hex string representing the raw CBOR
        attestation object received from the key */

		$attData = $this->parseAttestationObject( $info->response->attestationObject );

		// check info
		if ( false === $attData ) {
			// error generated in parseAttestationObject()
			return false;
		}

        if ( $attData->credId !== self::arrayToString( $info->rawId ) ) {
			$this->last_error[ $this->last_call ] = 'ao-id-mismatch';
			return false;
        }

        return (object) [
			'key' => $attData->keyBytes,
			'id' => $info->rawId,
		];

    }

    /**
    * generates a new key string for the physical key, fingerprint
    * reader or whatever to respond to on login
    * @param array $userKeys the existing webauthn field for the user from your database
    * @return boolean|object Object to pass to javascript webauthnAuthenticate or false on faliue
    */
    public function prepareAuthenticate( array $userKeys = [] )
    {
		$allowKeyDefaults = [
			'transports' =>  [ 'usb','nfc','ble','internal' ],
			'type' => 'public-key',
		];
        $allows = [];
		foreach ( $userKeys as $key) {
			if ( $this->isValidKey( $key ) ) {
				$allows[] = (object) ( [
					'id' => $key->id,
				] + $allowKeyDefaults );
			}
		}

        if ( ! count( $allows ) ) {
            /* including empty user, so they can't tell whether the user exists or not (need same result each
            time for each user) */
            $rb = md5( (string) time() );
            $allows[] = (object) ([
				'id' => self::stringToArray( $rb ),
			] + $allowKeyDefaults);
        }

        /* generate key request */
        $publickey = (object) [];
        $publickey->challenge = self::stringToArray( self::randomBytes(16) );
        $publickey->timeout = 60000;
        $publickey->allowCredentials = $allows;
        $publickey->userVerification = 'discouraged';
        $publickey->extensions = (object)array();
        // $publickey->extensions->txAuthSimple = 'Execute order 66';
        $publickey->rpId = str_replace('https://', '', $this->appid );

        return $publickey;
    }

    /**
    * validates a response for login or 2fa
    * requires info from the hardware via javascript given below
    * @param object $info supplied to the PHP script via POST, constructed by the Javascript given below, ultimately
    *        provided by the key
    * @param array $userKeys the exisiting webauthn field for the user from your
    *        database
    * @return object|null the matching key object from $userKeys for a valid authentication, null otherwise
    */
    public function authenticate( object $info, array $userKeys )
    {

		$this->last_call = __FUNCTION__;

		$this->last_error[ $this->last_call ] = false;

		// check info
		if ( ! $this->validateAuthenticateInfo( $info ) ) {
//			$this->last_error['authenticate'] = 'invalid-authenticate-info';
			return false;
		}

		$key = $this->findKeyById( $info->rawId, $userKeys );

		if ( false === $key ) {
			$this->last_error[ $this->last_call ] = 'no-matching-key';
			return false;
		}


        $bs = self::arrayToString( $info->response->authenticatorData );
        $ao = (object)array();

        $ao->rpIdHash = substr( $bs, 0, 32 );
        $ao->flags = ord( substr( $bs, 32, 1 ) );
        $ao->counter = substr( $bs, 33, 4 );

        $hashId = hash( 'sha256', $this->appid, true );

        if ( $hashId !== $ao->rpIdHash ) {
			$this->last_error[ $this->last_call ] = 'key-response-decode-hash-mismatch';
			return false;
        }

        /* experience shows that at least one device (OnePlus 6T/Pie (Android phone)) doesn't set this,
        so this test would fail. This is not correct according to the spec, so  pragmatically it may
        have to be removed */
        if ( ( $ao->flags & 0x1 ) != 0x1 ) {
			$this->last_error[ $this->last_call ] = 'key-response-decode-flags-mismatch';
			return false;
        } /* only TUP must be set */

        /* assemble signed data */
        $clientdata = self::arrayToString( $info->response->clientDataJSONarray );
        $signeddata = $hashId . chr( $ao->flags ) . $ao->counter . hash( 'sha256', $clientdata, true );

        if (count( $info->response->signature ) < 70) {
			$this->last_error[ $this->last_call ] = 'key-response-decode-signature-invalid';
			return false;
        }

        $signature = self::arrayToString($info->response->signature);

		$verify_result = openssl_verify( $signeddata, $signature, $key->key, OPENSSL_ALGO_SHA256 );

		if ( 1 === $verify_result ) {
			$this->last_error[ $this->last_call ] = false;
			return $key;
		} else if ( 0 === $verify_result ) {
			$this->last_error[ $this->last_call ] = 'key-not-verfied';
			return false;
		}

		$this->last_error[ $this->last_call ] = openssl_error_string();

		return false;

    }

	/**
	 *	Parse and validate Attestation object
	 *
	 *	@param array $ao_arr Attestation Object byte array
	 *	@return boolean|object attestedCredentialData false on failure
	 *
	 *	@see https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
	 */
	private function parseAttestationObject( array $ao_arr ) {

		//
		$ao_cbor = self::arrayToString( $ao_arr );
		$ao = (object)( \CBOR\CBOREncoder::decode( $ao_cbor ) );

		// begin validation
		if ( ! is_object( $ao ) ) {
			$this->last_error[ $this->last_call ] = 'ao-not-object';
			return false;
		}

        if ( empty( $ao ) ) {
			$this->last_error[ $this->last_call ] = 'ao-empty';
			return false;
        }

        if ( ! isset( $ao->fmt, $ao->authData ) ) {
			$this->last_error[ $this->last_call ] = 'ao-missing-property';
			return false;
        }

		if ( ! is_string( $ao->fmt ) ) {
			$this->last_error[ $this->last_call ] = 'ao-fmt-invalid';
			return false;
        }
		if ( ! ( $ao->authData instanceof \CBOR\Types\CBORByteString ) ) {
			$this->last_error[ $this->last_call ] = 'ao-authdata-invalid';
			return false;
		}

		if ( ! in_array( $ao->fmt, [ 'none', 'packed' ] ) ) {
			$this->last_error[ $this->last_call ] = 'ao-fmt-unsupported';
			return false;
		}

		$bs = $ao->authData->get_byte_string();

		if ( empty( $bs ) ) {
			$this->last_error[ $this->last_call ] = 'ao-authdata-empty';
			return false;
		}

		//
		$authData = (object) [
			'rpIdHash' => substr($bs, 0, 32),
			'flags' => ord(substr($bs, 32, 1)),
			'signCount' => substr($bs, 33, 4),
		];
		//
        // $ao->rpIdHash = substr($bs, 0, 32);
        // $ao->flags = ord(substr($bs, 32, 1));
        // $ao->signCount = substr($bs, 33, 4);

		if ( ! ( $authData->flags & 0x41 ) ) {
			$this->last_error[ $this->last_call ] = 'ao-flags-unsupported';
			return false;
        } /* TUP and AT must be set */


        $hashId = hash('sha256', $this->appid, true);

        if ( $hashId != $authData->rpIdHash ) {
			$this->last_error[ $this->last_call ] = 'ao-appid-mismatch';
			return false;
        }

		$attData = (object) [
			'aaguid' => substr($bs, 37, 16),
			'credIdLen' => ( ord( $bs[53] ) << 8 ) + ord( $bs[54] ),
		];
		$attData->credId = substr( $bs, 55, $attData->credIdLen );
		$attData->keyBytes = self::COSEECDHAtoPKCS(
			substr( $bs, 55 + $attData->credIdLen )
		);

		return $attData;

	}

	/**
	 *	Validates First argument of authenticate.
	 *	@param object $info
	 *	@return boolean
	 */
	private function validateRegisterInfo( object $info ) {
		/*
		$info
			->rawId					Uint8Array
			->response
				->attestationObject	Uint8Array : CBOR

		*/
		if ( ! isset( $info->rawId, $info->response ) ) {
			$this->last_error[ $this->last_call ] = 'info-missing-property';
			return false;
		}
		if ( ! is_array( $info->rawId ) || ! is_object( $info->response ) ) {
			$this->last_error[ $this->last_call ] = 'info-malformed-property';
			return false;
		}
		if ( ! isset( $info->response->attestationObject ) ) {
			$this->last_error[ $this->last_call ] = 'info-response-missing-property';
			return false;
		}
		if ( ! is_array( $info->response->attestationObject ) ) {
			$this->last_error[ $this->last_call ] = 'info-response-malformed-property';
			return false;
		}

		return true;

	}




	/**
	 *	Validates First argument of authenticate.
	 *	@param object $info
	 *	@return boolean
	 */
	private function validateAuthenticateInfo( object $info ) {
		/*
		$info
			->rawId array				Uint8Array
			->originalChallenge			Uint8Array
			->response
				->clientData
					->challenge			base64string
					->origin			string URL
					->type 				string 'webauthn.get'
				->clientDataJSONarray	Uint8Array
				->authenticatorData		Uint8Array
				->signature 			Uint8Array
		*/
		// check existence 1st level
		if ( ! isset( $info->rawId, $info->originalChallenge, $info->response ) ) {
			$this->last_error[ $this->last_call ] = 'info-missing-property';
			return false;
		}
		// check types 1st level
		if ( ! is_array( $info->rawId ) || ! is_array( $info->originalChallenge ) || ! is_object( $info->response ) ) {
			$this->last_error[ $this->last_call ] = 'info-malformed-value';
			return false;
		}

		// check existence 2nd level
		if ( ! isset( $info->response->clientData, $info->response->clientDataJSONarray, $info->response->authenticatorData, $info->response->signature ) ) {
			$this->last_error[ $this->last_call ] = 'info-response-missing-property';
			return false;
		}
		// check types 2nd level
		if ( ! is_object( $info->response->clientData ) || ! is_array( $info->response->clientDataJSONarray ) || ! is_array( $info->response->authenticatorData ) || ! is_array( $info->response->signature ) ) {
			$this->last_error[ $this->last_call ] = 'info-response-malformed-value';
			return false;
		}

		// check existence 3rd level
		if ( ! isset(
				$info->response->clientData->challenge,
				$info->response->clientData->origin,
				$info->response->clientData->type
			)
	 	) {
			$this->last_error[ $this->last_call ] = 'info-clientdata-missing-property';
			return false;
		}

		// check types 3rd level
		if (
			! is_string( $info->response->clientData->challenge ) ||
			! is_string( $info->response->clientData->origin ) ||
			! is_string( $info->response->clientData->type )
	 	) {
			$this->last_error[ $this->last_call ] = 'info-clientdata-malformed-value';
			return false;
		}

		if ( $info->response->clientData->type != 'webauthn.get') {
			$this->last_error[ $this->last_call ] = "info-wrong-type";
			return false;
        }


		/* cross-check challenge */
        if ( $info->response->clientData->challenge
					!==
			rtrim( strtr( base64_encode( self::arrayToString( $info->originalChallenge ) ), '+/', '-_'), '=')
		) {
			$this->last_error[ $this->last_call ] = 'info-challenge-mismatch';
			return false;
        }

		/* cross check origin */
        $origin = parse_url( $info->response->clientData->origin );

        if ( strpos( $origin['host'], $this->appid ) !== ( strlen( $origin['host'] ) - strlen( $this->appid ) ) ) {

			$this->last_error[ $this->last_call ] = 'info-origin-mismatch';
			return false;
        }


		return true;


	}


	/**
	 *	Find key by ID
	 *	@param array $keyId
	 *	@param array $keys Contains key objects (object) [ 'id' => [ int, int, ...], 'key' => '-----BEGIN PUBLIC KEY--...' ]
	 */
	private function findKeyById( array $keyId, array $keys ) {

		$keyIdString = implode( ',', $keyId );

        foreach ( $keys as $key ) {
			// check for key format
			if ( ! $this->isValidKey( $key ) ) {
				continue;
			}
            if ( implode(',', $key->id ) === $keyIdString ) {
                return $key;
            }
        }
		return false;
	}

	/**
	 *	@param object $key
	 *	@return boolean
	 */
	private function isValidKey( $key ) {
		 return is_object( $key ) && isset( $key->id ) && is_array( $key->id ) && isset( $key->key ) && is_string( $key->key );
	}


    /**
    * convert an array of uint8's to a binary string
    * @param array $a to be converted (array of unsigned 8 bit integers)
    * @return string converted to bytes
    */
    private static function arrayToString($a)
    {
        $s = '';
        foreach ($a as $c) {
            $s .= chr($c);
        }
        return $s;
    }

    /**
    * convert a binary string to an array of uint8's
    * @param string $s to be converted
    * @return array converted to array of unsigned integers
    */
    private static function stringToArray($s)
    {
        /* convert binary string to array of uint8 */
        $a = [];
        for ($idx = 0; $idx < strlen($s); $idx++) {
            $a[] = ord($s[$idx]);
        }
        return $a;
    }

    /**
    * convert a public key from the hardware to PEM format
    * @param string $key to be converted to PEM format
    * @return string converted to PEM format
    */
    private function pubkeyToPem($key)
    {
        /* see https://github.com/Yubico/php-u2flib-server/blob/master/src/u2flib_server/U2F.php */
        if (strlen($key) !== 65 || $key[0] !== "\x04") {
            return null;
        }
        /*
        * Convert the public key to binary DER format first
        * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
        *
        *  SEQUENCE(2 elem)                        30 59
        *   SEQUENCE(2 elem)                       30 13
        *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
        *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
        *   BIT STRING(520 bit)                    03 42 ..key..
        */
        $der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\x00".$key;
        $pem  = "-----BEGIN PUBLIC KEY-----\x0A";
        $pem .= chunk_split(base64_encode($der), 64, "\x0A");
        $pem .= "-----END PUBLIC KEY-----\x0A";
        return $pem;
    }

    /**
     * Convert COSE ECDHA to PKCS
     * @param string binary string to be converted
     * @return string converted public key
     */
    private function COSEECDHAtoPKCS($binary)
    {
        $cosePubKey = \CBOR\CBOREncoder::decode($binary);

        if (! isset($cosePubKey[3] /* cose_alg */)) {
            $this->oops('cannot decode key response (8)');
        }

        switch ($cosePubKey[3]) {
            case self::ES256:
                /* COSE Alg: ECDSA w/ SHA-256 */
                if (! isset($cosePubKey[-1] /* cose_crv */)) {
                    $this->oops('cannot decode key response (9)');
                }

                if (! isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('cannot decode key response (10)');
                }

                if ($cosePubKey[-1] != 1 /* cose_crv_P256 */) {
                    $this->oops('cannot decode key response (14)');
                }

                if (!isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('x coordinate for curve missing');
                }

                if (! isset($cosePubKey[1] /* cose_kty */)) {
                    $this->oops('cannot decode key response (7)');
                }

                if (! isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('cannot decode key response (11)');
                }

                if (!isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('y coordinate for curve missing');
                }

                if ($cosePubKey[1] != 2 /* cose_kty_ec2 */) {
                    $this->oops('cannot decode key response (12)');
                }

                $x = $cosePubKey[-2]->get_byte_string();
                $y = $cosePubKey[-3]->get_byte_string();
                if (strlen($x) != 32 || strlen($y) != 32) {
                    $this->oops('cannot decode key response (15)');
                }
                $tag = "\x04";
                return $this->pubkeyToPem($tag.$x.$y);
                break;
            case self::RS256:
                /* COSE Alg: RSASSA-PKCS1-v1_5 w/ SHA-256 */
                if (!isset($cosePubKey[-2])) {
                    $this->oops('RSA Exponent missing');
                }
                if (!isset($cosePubKey[-1])) {
                    $this->oops('RSA Modulus missing');
                }
                $e = new BigInteger(bin2hex($cosePubKey[-2]->get_byte_string()), 16);
                $n = new BigInteger(bin2hex($cosePubKey[-1]->get_byte_string()), 16);
                $rsa = new RSA();
                $rsa->loadKey(compact('e', 'n'));
                return $rsa->getPublicKey();
            default:
                $this->oops('cannot decode key response (13)');
        }
    }

    /**
    * shim for random_bytes which doesn't exist pre php7
    * @param int $length the number of bytes required
    * @return string length cryptographically random bytes
    */
    private static function randomBytes($length)
    {
      if (function_exists('random_bytes')) {
          return random_bytes($length);
      } else if (function_exists('openssl_random_pseudo_bytes')) {
          $bytes = openssl_random_pseudo_bytes($length, $crypto_strong);
          if (! $crypto_strong) {
              throw new \Exception("openssl_random_pseudo_bytes did not return a cryptographically strong result", 1);
          }
          return $bytes;
      } else {
          throw new \Exception("Neither random_bytes not openssl_random_pseudo_bytes exists. PHP too old? openssl PHP extension not installed?", 1);
      }
    }

    /**
    * just an abbreviation to throw an error: never returns
    * @param string $s error message
    * @param int $c error code (0 for user error, 1 for incorrect usage)
    *
    */
    private function oops($s, $c=0)
    {
        error_log("oops: {$s} {$c}");
        throw new \Exception($s, $c);
    }

    protected function getUrlSuffix()
    {
    }
}

<?php

/*
@see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
*/

namespace TwoFactorWebauthn\Webauthn;

if ( ! defined('ABSPATH') ) {
	die('FU!');
}


class Struct {

	// /**
	//  *	@return stdClass representation of object
	//  */
	public function toPlainObject() {
		return (object) array_map( [ $this, '_toPlainObject' ], get_object_vars( $this ) );
	}

	/**
	 *	@return stdClass representation of $data
	 */
	private function _toPlainObject( $data ) {
		if ( is_scalar( $data ) ){
			return $data;
		}
		if ( is_array( $data ) ) {
			return array_map( [ $this, '_toPlainObject' ], $data );
		} else if ( method_exists( $data, 'toPlainObject' ) ) {
			return $data->toPlainObject();
		}
		return $data;
	}

	public function set( $prop, $value ) {
		if ( ! isset( $this->$prop ) ) {
			$class = get_class($this);
			throw new \Exception( "Property {$class}::{$prop} does not exist" );
		}

		if ( $this->$prop instanceof Struct ) {
			$cls = get_class( $this->$prop );
			$value = $cls::fromPlainObject( $value );
		}
		$this->$prop = $value;
	}

	public static function fromPlainObject( $obj ) {
		$class = get_called_class();
		$vars = get_object_vars( $obj );
		$inst = new $class();
		foreach ( array_keys( get_class_vars( $class ) ) as $prop ) {
			if ( isset( $obj->$prop ) ) {
				$inst->set( $prop, $obj->$prop );
			}
		}
		return $inst;
	}

	/**
	 *	@param mixed $cbor byte string or array
	 */
	public static function fromCBOR( $cbor ) {
		$class = get_called_class();
		if ( is_array( $cbor ) ) {
			$cbor = implode( '', array_map( 'chr', $cbor ) );
		}
		$obj = (object)(\CBOR\CBOREncoder::decode( $cbor ));
		return $class::fromPlainObject( $obj );
	}



	public function __set( $prop, $value ) {
		throw new \Exception( "Property $prop does not exist" );
	}

}

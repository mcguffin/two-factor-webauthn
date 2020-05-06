import $ from 'jquery'

/**
 *	Stolen from https://github.com/davidearl/webauthn
 */
function webauthnAuthenticate( pubKeyAuth, cb ) {

	const originalChallenge = pubKeyAuth.challenge;
	const pk = Object.assign( {}, pubKeyAuth )

	pk.challenge = new Uint8Array( pubKeyAuth.challenge )
	pk.allowCredentials = pk.allowCredentials.map( k => {
		let ret = Object.assign( {}, k )
		ret.id = new Uint8Array(k.id);
		return ret
	} )

	/* ask the browser to prompt the user */
	navigator.credentials.get( { publicKey: pk } )
		.then( aAssertion => {
			// console.log("Credentials.Get response: ", aAssertion);
			var ida = [];
			(new Uint8Array(aAssertion.rawId)).forEach(function(v){ ida.push(v); });
			var cd = JSON.parse(String.fromCharCode.apply(null,
														  new Uint8Array(aAssertion.response.clientDataJSON)));
			var cda = [];
			(new Uint8Array(aAssertion.response.clientDataJSON)).forEach(function(v){ cda.push(v); });
			var ad = [];
			(new Uint8Array(aAssertion.response.authenticatorData)).forEach(function(v){ ad.push(v); });
			var sig = [];
			(new Uint8Array(aAssertion.response.signature)).forEach(function(v){ sig.push(v); });
			var info = {
				type: aAssertion.type,
				originalChallenge: originalChallenge,
				rawId: ida,
				response: {
					authenticatorData: ad,
					clientData: cd,
					clientDataJSONarray: cda,
					signature: sig
				}
			};
			cb( true, JSON.stringify( info ) );
		})
		.catch( aErr => {
			if ( "name" in aErr ) {
				// change: distiguish between errors
				if ( aErr.name == "NotAllowedError" ) {
					cb( false, 'not-allowed' );
				} else if ( aErr.name == "AbortError" || aErr.name == "NS_ERROR_ABORT" ) {
					cb( false, 'abort' );
				} else {
					cb( false, aErr.toString() );
				}
			} else {
				cb(false, aErr.toString());
			}
		});
}

/**
 *	Stolen from https://github.com/davidearl/webauthn
 */
function webauthnRegister(key, callback){

	let publicKey = Object.assign( {}, key.publicKey );

	publicKey.attestation = undefined;
	publicKey.challenge = new Uint8Array( publicKey.challenge ); // convert type for use by key
	publicKey.user.id = new Uint8Array( publicKey.user.id );

	// console.log(key);
	navigator.credentials.create( { publicKey } )
		.then(function (aNewCredentialInfo) {
			// console.log("Credentials.Create response: ", aNewCredentialInfo);
			var cd = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)));
			if ( key.b64challenge !== cd.challenge ) {
				callback(false, 'key returned something unexpected (1)');
			}
			if ('https://'+key.publicKey.rp.name != cd.origin) {
				return callback(false, 'key returned something unexpected (2)');
			}
			if (! ('type' in cd)) {
				return callback(false, 'key returned something unexpected (3)');
			}
			if (cd.type != 'webauthn.create') {
				return callback(false, 'key returned something unexpected (4)');
			}

			var ao = [];
			(new Uint8Array(aNewCredentialInfo.response.attestationObject)).forEach(function(v){
				ao.push(v);
			});
			var rawId = [];
			(new Uint8Array(aNewCredentialInfo.rawId)).forEach(function(v){
				rawId.push(v);
			});
			var info = {
				rawId: rawId,
				id: aNewCredentialInfo.id,
				type: aNewCredentialInfo.type,
				response: {
					attestationObject: ao,
					clientDataJSON:
					  JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)))
				}
			};
			callback(true, JSON.stringify(info));
		})
		.catch(function (aErr) {
			if (
				("name" in aErr) && (aErr.name == "AbortError" || aErr.name == "NS_ERROR_ABORT")
				|| aErr.name == 'NotAllowedError'
			) {
				callback(false, 'abort');
			} else {
				callback(false, aErr.toString());
			}
		});
}

/**
 *	@param ArrayBuffer arrayBuf
 *	@return Array
 */
const buffer2Array = arrayBuf => [ ... (new Uint8Array( arrayBuf )) ];

const register = ( opts, callback ) => {

	const { action, payload, _wpnonce } = opts;

	webauthnRegister( payload, (success,info) => {
		$.ajax({
			url: wp.ajax.settings.url,
			method: 'post',
			data: {
				action: action,
				payload: info,
				_wpnonce: _wpnonce
			},
			success: callback
		})
	})
}


const login = ( opts, callback ) => {

	const { action, payload, _wpnonce } = opts;

	webauthnAuthenticate( payload, ( success, info ) => {
		callback( { success, result: info } )
	})
}

const sendRequest = ( opts, callback ) => {

	const { action, payload, _wpnonce } = opts;

	$.ajax({
		url: wp.ajax.settings.url,
		method: 'post',
		data: {
			action: action,
			payload: payload,
			_wpnonce: _wpnonce
		},
		success:callback
	})
}


const editKey = ( opts, callback ) => {

}

module.exports = {
	register, login, sendRequest
}

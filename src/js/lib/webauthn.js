import $ from 'jquery'

/**
 *	@param ArrayBuffer arrayBuf
 *	@return Array
 */
const buffer2Array = arrayBuf => [ ... (new Uint8Array( arrayBuf )) ];

const register = ( opts, callback ) => {

	const { createOpts } = opts;

	createOpts.attestation = 'none';
	createOpts.challenge = new Uint8Array( createOpts.challenge );
	createOpts.user.id = new Uint8Array( createOpts.user.id );
	delete(createOpts.user.icon)

	//credentialCreateOpts.rp.id = new Uint8Array( credentialCreateOpts.rp.id );
	createOpts.authenticatorSelection.authenticatorAttachment = undefined;
	createOpts.authenticatorSelection.requireResidentKey = undefined;
console.log('credentials.create')
console.log(createOpts)
	let res = navigator.credentials.create( { publicKey: createOpts } )
		.then( credential => {
console.log('credentials.create result')
console.log(credential)

			const credentialJSON = {
				id: credential.id,
				rawId: buffer2Array( credential.rawId ),
				response: {
					// AuthenticatorAttestationResponse
					attestationObject: buffer2Array( credential.response.attestationObject ), // cbor 2 array
					clientDataJSON: String.fromCharCode.apply( null, new Uint8Array( credential.response.clientDataJSON ) ),
				},
				type: credential.type
			}

			$.ajax({
				url: wp.ajax.settings.url,
				method: 'post',
				data: {
					action: 'webauthn-register',
					credential: JSON.stringify(credentialJSON),
					_ajax_nonce: opts.ajaxNonce
				},
				success: callback
			})

		})
		.catch( err => {
			console.error( err )
		})
	console.log(res)

}


const login = ( opts, callback ) => {

	const { action, authOpts, _wpnonce } = opts;

	authOpts.challenge = new Uint8Array( authOpts.challenge );
	authOpts.allowCredentails = authOpts.allowCredentails.map( c => {
		c.id = new Uint8Array( c.id )
		c.transports = ["usb","nfc","ble","internal"]
		return c
	} );

console.log('credentials.get')
console.log(authOpts);

	let res = navigator.credentials.get( { publicKey: authOpts } )
		.then( credentials => {
console.log('credentials.get result')
console.log( credentials );
		})
		// .catch( err => {
		// 	console.error( err )
		// })
console.log(res)
}

const deleteKey = ( opts, callback ) => {

	$.ajax({
		url: wp.ajax.settings.url,
		method: 'post',
		data: opts,
		success:callback
	})
}


module.exports = {
	register, login, deleteKey
}

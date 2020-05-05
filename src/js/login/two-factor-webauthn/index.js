import $ from 'jquery'
import { login } from 'davidearl-webauthn'

const maxAttempts = 5

/**
 *	Some Password Managers (like nextcloud passwrds) seem to disturb webauthn.
 *	We retry a to get the key a couple of times
 */
const auth = ( attempt = 1 ) => {
	login( window.webauthnL10n, response => {
		if ( response.success ) {
			$('#webauthn_response').val( response.result )
			$( '#loginform' ).submit()
		} else if ( attempt < maxAttempts && 'abort' === response.result  ) {
			setTimeout( () => auth( attempt + 1 ), 500 )
			console.error( 'Failed attempt', attempt, 'of', maxAttempts );
		} else {
			console.error( 'Authentication Failed', response.result, attempt );
		}
	} );
}


if ( ! window.webauthnL10n ) {
	console.error( 'webauthL10n is not defined' );
};
$(document).ready( () => auth() );

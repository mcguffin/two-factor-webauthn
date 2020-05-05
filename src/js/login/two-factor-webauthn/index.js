import $ from 'jquery'
import { login } from 'davidearl-webauthn'

const maxAttempts = 5

/**
 *	Some Password Managers (like nextcloud passwords) seem to abort the
 *	key browser dialog.
 *	We have to retry a couple of times to
 */
const auth = ( attempt = 1 ) => {
	login( window.webauthnL10n, response => {
		if ( response.success ) {
			$('#webauthn_response').val( response.result )
			$( '#loginform' ).submit()
		} else if ( attempt < maxAttempts && 'not-allowed' === response.result  ) {
			setTimeout( () => auth( attempt + 1 ), 750 )
			console.warn( 'Failed to connect to hardware. Attempt', attempt, 'of', maxAttempts );
		} else {
			console.error( 'Authentication Failed', response.result, attempt );
		}
	} );
}

if ( ! window.webauthnL10n ) {
	console.error( 'webauthL10n is not defined' );
};

$(document).ready( () => auth() );

import $ from 'jquery'
import { login, isWebauthnSupported } from 'davidearl-webauthn'

/**
 *	Some Password Managers (like nextcloud passwords) seem to abort the
 *	key browser dialog.
 *	We have to retry a couple of times to
 */
const auth = () => {
	$('.webauthn-retry').removeClass('visible')
	login( window.webauthnL10n, response => {
		if ( response.success ) {
			$('#webauthn_response').val( response.result )
			$( '#loginform' ).submit()
		} else {
			// show retry-button
			$('.webauthn-retry').addClass('visible')
		}
	} );
}

if ( ! window.webauthnL10n ) {
	console.error( 'webauthL10n is not defined' );
};

if ( isWebauthnSupported ) {
	$(document)
		.ready( () => auth() )
		.on('click','.webauthn-retry-link', () => auth() );
} else {
	// show message
	$('.webauthn-unsupported').addClass('visible')
}

import $ from 'jquery'
import { login } from 'davidearl-webauthn'


if ( ! window.webauthnL10n ) {
	window.console.error( 'u2fL10n is not defined' );
};

setTimeout(() => {
	login( window.webauthnL10n, response => {
		if ( response.success ) {
			$('#webauthn_response').val( response.result )
			$( '#loginform' ).submit()
		} else {
			window.console.error( 'Authentication Failed', response.result );
		}
	} );
}, 1000 );

import $ from 'jquery'
import { login } from 'webauthn'


if ( ! window.webauthnL10n ) {
	window.console.error( 'u2fL10n is not defined' );
};

login( window.webauthnL10n, result => {

} );

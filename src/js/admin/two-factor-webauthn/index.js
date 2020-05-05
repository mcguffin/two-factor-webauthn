import { register, login, deleteKey } from 'davidearl-webauthn'

(function($){

	$(document).on( 'click', '#webauthn-register-key', e => {

		e.preventDefault();

		const opts = JSON.parse( $(e.target).attr('data-create-options') );

		register( opts, response => {
			$('#webauthn-keys').append(response.html)
		});

	});

	$(document).on('click','.webauthn-action-button', e => {
		e.preventDefault();
		const opts = JSON.parse( $(e.target).attr('data-action') );
		const btn = e.target;
		if ( opts.action === 'webauthn-test-key' ) {
			login( opts, function( response ) {
				// send that crap to server
				console.log(response)
				$(btn).append('<span class="dashicons dashicons-yes-alt"></span>')
			} );
		} else if ( opts.action === 'webauthn-delete-key' ) {
			deleteKey( opts, function( response ) {
				// remove
				if ( response.success ) {

					$(btn).closest('.webauthn-key').remove();
				}
			} );
		}
	});

})(jQuery);

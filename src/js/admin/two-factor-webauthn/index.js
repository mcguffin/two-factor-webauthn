import $ from 'jquery'
import { register, login, sendRequest } from 'davidearl-webauthn'



const editKey = ( editLabel, opts ) => {

	const { action, payload, _wpnonce } = opts


	// console.log($editLabel.prop( 'contenteditable' ));
	const stopEditing = ( save = false ) => {
		let newLabel = $(editLabel).text()
		$(editLabel).prop( 'contenteditable', false );
		$(document).off( 'keydown' )
		$(editLabel).off( 'blur' )
		if ( save && prevLabel !== newLabel ) {

			$('<span class="spinner"></span>').insertAfter(editLabel)

			sendRequest(
				{
					action,
					payload: { md5id: payload, label: newLabel },
					_wpnonce
				},
				response => {
					$(editLabel).next('.spinner').remove()
				}
			);
		} else if ( ! save ) {
			$(editLabel).text(prevLabel)
		}
	}

	const prevLabel = $(editLabel).text()

	$(editLabel).prop( 'contenteditable', true );

	$(document).on( 'keydown', e => {
		if ( e.which === 13 ) {
			stopEditing( true )
			e.preventDefault()
		} else if ( e.which === 27 ) {
			stopEditing( true )
		}
	} )

	// focus and select
	$(editLabel).on( 'blur', e => stopEditing( true ) )

	$(editLabel).focus()

	document.execCommand( 'selectAll', false, null );

}

$(document).on( 'click', '#webauthn-register-key', e => {

	e.preventDefault();

	const opts = JSON.parse( $(e.target).attr('data-create-options') );

	register( opts, response => {

		// 2DO: error handling

		let $keyItem = $(response.html).appendTo('#webauthn-keys')
		let $keyLabel = $keyItem.find('.webauthn-label')

		editKey(
			$keyLabel.get(0),
			JSON.parse( $keyLabel.attr('data-action') )
		);
	});

});

$(document).on('click','.webauthn-action', e => {
	const opts = JSON.parse( $(e.target).attr('data-action') );
	const btn = e.target;
	const $keyEl = $(e.target).closest('.webauthn-key')
	const { action, payload, _wpnonce } = opts

	if ( opts.action === 'webauthn-test-key' ) {
		e.preventDefault();
		login( opts, result => {
			// send that crap to server
			console.log(result)
			sendRequest( { action, payload: result.result, _wpnonce }, response => {
				console.log( response )
				$(btn).append('<span class="dashicons dashicons-yes-alt"></span>')
			})
		} );
	} else if ( opts.action === 'webauthn-delete-key' ) {
		e.preventDefault();
		sendRequest( opts, function( response ) {
			// remove
			if ( response.success ) {

				$(btn).closest('.webauthn-key').remove();
			}
		} );
	} if ( opts.action === 'webauthn-edit-key' ) {
		if ( 'true' !== $(e.currentTarget).prop( 'contenteditable' ) ) {
			e.preventDefault();
			editKey( e.currentTarget, opts );
		}
	}
});

import $ from 'jquery'
import { register, login, sendRequest, isWebauthnSupported } from 'davidearl-webauthn'



const editKey = ( editLabel, opts ) => {

	const { action, payload, _wpnonce } = opts


	// console.log($editLabel.prop( 'contenteditable' ));
	const stopEditing = ( save = false ) => {
		let newLabel = $(editLabel).text()
		$(editLabel).text(newLabel)
		$(editLabel).prop( 'contenteditable', false );
		$(document).off( 'keydown' )
		$(editLabel).off( 'blur' )
		if ( save && prevLabel !== newLabel ) {
			$(editLabel).addClass('busy')

			sendRequest(
				{
					action,
					payload: { md5id: payload, label: newLabel },
					_wpnonce
				},
				response => {
					$(editLabel).removeClass('busy')
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
	$(editLabel)
		.on( 'blur', e => stopEditing( true ) )
		.on( 'paste', e => {
		    e.preventDefault();
		    let text = (e.originalEvent || e).clipboardData.getData('text/plain');
		    document.execCommand("insertHTML", false, text);
		} )

	$(editLabel).focus()

	document.execCommand( 'selectAll', false, null );

}

$(document).on( 'click', '#webauthn-register-key', e => {

	e.preventDefault();

	$(e.target).next('.webauthn-error').remove()
	let $btn = $(e.target).addClass('busy')

	const opts = JSON.parse( $(e.target).attr('data-create-options') );

	register( opts, response => {
		$btn.removeClass('busy')
		if ( response.success ) {
			let $keyItem = $(response.html).appendTo('#webauthn-keys')
			let $keyLabel = $keyItem.find('.webauthn-label')

			editKey(
				$keyLabel.get(0),
				JSON.parse( $keyLabel.attr('data-action') )
			);
		} else {
			$(`<span class="webauthn-error description">${response.message}</span>`).insertAfter('#webauthn-register-key')
		}
	});

});

if ( isWebauthnSupported ) {
	$(document).on('click','.webauthn-action', e => {
		e.preventDefault();
		const $btn = $(e.target).closest('.webauthn-action');
		const opts = JSON.parse( $btn.attr('data-action') );
		const $keyEl = $(e.target).closest('.webauthn-key')
		const { action, payload, _wpnonce } = opts



		if ( opts.action === 'webauthn-test-key' ) {
			e.preventDefault();
			$keyEl.find('.notice').remove();
			$btn.addClass('busy');
			login( opts, result => {
				// send that crap to server

				if ( ! result.success ) {
					$keyEl.append(`<div class="notice notice-inline notice-warning">${result.message}</div>`)
					return;
				}
				sendRequest( { action, payload: result.result, _wpnonce }, response => {
					if ( response.success ) {
						$btn.find('[data-tested]').attr('data-tested','tested')
					} else {
						$btn.find('[data-tested]').attr('data-tested','fail')
						$keyEl.append(`<div class="notice notice-inline notice-error">${response.message}</div>`)
					}
					$btn.removeClass('busy');
				})
			} );
		} else if ( opts.action === 'webauthn-delete-key' ) {
			$keyEl.addClass('busy');
			e.preventDefault();
			sendRequest( opts, function( response ) {
				// remove
				if ( response.success ) {

					$keyEl.remove();
				}
			} );
		} if ( opts.action === 'webauthn-edit-key' ) {
			if ( 'true' !== $(e.currentTarget).prop( 'contenteditable' ) ) {
				e.preventDefault();
				editKey( e.currentTarget, opts );
			}
		}
	});
} else {
	$('.webauthn-unsupported').removeClass('hidden');
	$('.webauthn-supported').addClass('hidden');
}

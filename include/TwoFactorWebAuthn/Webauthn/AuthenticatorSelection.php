<?php

/*
@see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/authenticatorSelection
*/

namespace TwoFactorWebauthn\Webauthn;

class AuthenticatorSelection extends Struct {

	public string $authenticatorAttachment = 'platform'; // platform | cross-platform
	public boolean $requireResidentKey; // true: SoftU2F reg broken, but auth works with sensor, false: SoftU2F reg works but auth breaks
	public string $userVerification = 'discouraged'; // required / preferred / discouraged

}

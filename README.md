Two Factor WebAuthn
===================

WebAuthn module for the [Two Factor](https://github.com/WordPress/two-factor/) WordPress plugin.

Incorporates a modified version of [WebAuthn by David Earl](https://github.com/davidearl/webauthn/).

Current Status
--------------
This plugin is currently a proof of concept. Better not se it in a production environment.

See this issue on [WebAuthn in Two Factor](https://github.com/WordPress/two-factor/issues/232).


Installation
------------

### Production (using Github Updater – recommended for Multisite)
 - Install [Andy Fragen's GitHub Updater](https://github.com/afragen/github-updater) first.
 - In WP Admin go to Settings / GitHub Updater / Install Plugin. Enter `/two-factor-webauthn` as a Plugin-URI.

### Development
 - cd into your plugin directory
 - $ `git clone `
 - $ `cd two-factor-webauthn`
 - $ `npm install && npm run dev`

ToDo
----
 - [ ] User-Admin: allow adding token for others
 - [x] User-Admin: Save key tested state
 - [x] Save key creation and usage timestamp
 - [x] UI: disable key generation if WebAuthn is not supported
 - [x] Login UI: show 
 - [x] Test: Windows Hello, Hardware Key, Android
 - [x] WebAuthn
   - [x] Function arg processing and return values

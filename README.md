Two Factor WebAuthn
===================

WebAuthn module for the [Two Factor](https://github.com/WordPress/two-factor/) WordPress plugin.

Incorporates a modified version of [WebAuthn by David Earl](https://github.com/davidearl/webauthn/).

Current Status
--------------
This plugin is currently in beta stadium. I still hope to have it merged into 
[Two Factor](https://github.com/WordPress/two-factor) later, but the response doesn't look very promising yet: https://github.com/WordPress/two-factor/issues/232

Installation
------------
### Production (using Github Updater – recommended for Multisite)
 - Install [Andy Fragen's GitHub Updater](https://github.com/afragen/github-updater) first.
 - In WP Admin go to Settings / GitHub Updater / Install Plugin. Enter `mcguffin/two-factor-webauthn` as a Plugin-URI.

### Development
```
cd wp-content/plugins
git clone git@github.com:mcguffin/two-factor-webauthn.git
cd two-factor-webauthn
npm install
npm run dev
```

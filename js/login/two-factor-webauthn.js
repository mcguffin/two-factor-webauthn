!function(){var n={};(function(e){(function(){"use strict";(a="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&a.__esModule;var a,t="credentials"in navigator;n={login:function(n,e){n.action;var a=n.payload;n._wpnonce,function(n,e){var a=n.challenge,t=Object.assign({},n);t.challenge=new Uint8Array(n.challenge),t.allowCredentials=t.allowCredentials.map(function(n){var e=Object.assign({},n);return e.id=new Uint8Array(n.id),e}),navigator.credentials.get({publicKey:t}).then(function(n){var t=[];new Uint8Array(n.rawId).forEach(function(n){t.push(n)});var i=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON))),o=[];new Uint8Array(n.response.clientDataJSON).forEach(function(n){o.push(n)});var r=[];new Uint8Array(n.response.authenticatorData).forEach(function(n){r.push(n)});var l=[];new Uint8Array(n.response.signature).forEach(function(n){l.push(n)});var u={type:n.type,originalChallenge:a,rawId:t,response:{authenticatorData:r,clientData:i,clientDataJSONarray:o,signature:l}};e(!0,JSON.stringify(u))}).catch(function(n){console.log(n),e(!1,"name"in n?n.name+": "+n.message:n.toString())})}(a,function(n,a){e(n?{success:!0,result:a}:{success:!1,message:a})})},isWebauthnSupported:t}}).call(this)}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(e){(function(){"use strict";var a,t=(a="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&a.__esModule?a:{default:a},i=function(){(0,t.default)(".webauthn-retry").removeClass("visible"),(0,n.login)(window.webauthnL10n,function(n){n.success?((0,t.default)("#webauthn_response").val(n.result),(0,t.default)("#loginform").submit()):(0,t.default)(".webauthn-retry").addClass("visible")})};window.webauthnL10n||console.error("webauthL10n is not defined"),n.isWebauthnSupported?(0,t.default)(document).ready(i).on("click",".webauthn-retry-link",i):(0,t.default)(".webauthn-unsupported").addClass("visible")}).call(this)}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
!function(){var n={};(function(e){"use strict";var t;(t="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&t.__esModule;function o(n){return(o="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(n){return typeof n}:function(n){return n&&"function"==typeof Symbol&&n.constructor===Symbol&&n!==Symbol.prototype?"symbol":typeof n})(n)}var a="credentials"in navigator;n={login:function(n,e){n.action;var t,a,r,i,l=n.payload;n._wpnonce,a=function(n,t){e({success:n,result:t})},r=(t=l).challenge,(i=Object.assign({},t)).challenge=new Uint8Array(t.challenge),i.allowCredentials=i.allowCredentials.map(function(n){var e=Object.assign({},n);return e.id=new Uint8Array(n.id),e}),navigator.credentials.get({publicKey:i}).then(function(n){var e=[];new Uint8Array(n.rawId).forEach(function(n){e.push(n)});var t=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON))),o=[];new Uint8Array(n.response.clientDataJSON).forEach(function(n){o.push(n)});var i=[];new Uint8Array(n.response.authenticatorData).forEach(function(n){i.push(n)});var l=[];new Uint8Array(n.response.signature).forEach(function(n){l.push(n)});var u={type:n.type,originalChallenge:r,rawId:e,response:{authenticatorData:i,clientData:t,clientDataJSONarray:o,signature:l}};a(!0,JSON.stringify(u))}).catch(function(n){console.log(n),"name"in n?(console.log(o(n)),console.log(n.name),console.log(n.message),"NotAllowedError"==n.name?a(!1,"not-allowed"):"AbortError"==n.name||"NS_ERROR_ABORT"==n.name?a(!1,"abort"):a(!1,n.toString())):a(!1,n.toString())})},isWebauthnSupported:a}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(e){"use strict";var t,o=(t="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&t.__esModule?t:{default:t},a=function(){(0,o.default)(".webauthn-retry").removeClass("visible"),(0,n.login)(window.webauthnL10n,function(n){n.success?((0,o.default)("#webauthn_response").val(n.result),(0,o.default)("#loginform").submit()):(0,o.default)(".webauthn-retry").addClass("visible")})};window.webauthnL10n||console.error("webauthL10n is not defined"),n.isWebauthnSupported?(0,o.default)(document).ready(function(){return a()}).on("click",".webauthn-retry-link",function(){return a()}):(0,o.default)(".webauthn-unsupported").addClass("visible")}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
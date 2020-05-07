!function(){var e={};(function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n};function o(e){return(o="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}var r="credentials"in navigator;e={register:function(e,t){var n=e.action,o=e.payload,r=e._wpnonce;!function(e,t){var n=Object.assign({},e.publicKey);n.attestation=void 0,n.challenge=new Uint8Array(n.challenge),n.user.id=new Uint8Array(n.user.id),navigator.credentials.create({publicKey:n}).then(function(n){var a=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)));if(e.b64challenge!==a.challenge&&t(!1,"key returned something unexpected (1)"),"https://"+e.publicKey.rp.name!=a.origin)return t(!1,"key returned something unexpected (2)");if(!("type"in a))return t(!1,"key returned something unexpected (3)");if("webauthn.create"!=a.type)return t(!1,"key returned something unexpected (4)");var o=[];new Uint8Array(n.response.attestationObject).forEach(function(e){o.push(e)});var r=[];new Uint8Array(n.rawId).forEach(function(e){r.push(e)});var i={rawId:r,id:n.id,type:n.type,response:{attestationObject:o,clientDataJSON:JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)))}};t(!0,JSON.stringify(i))}).catch(function(e){console.log(e),"name"in e?(console.log(e.name),"AbortError"==e.name||"NS_ERROR_ABORT"==e.name?t(!1,"abort"):t(!1,e.name)):t(!1,e.toString())})}(o,function(e,o){response.success?a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:o,_wpnonce:r},success:t}):t({success:!1,error:o})})},login:function(e,t){e.action;var n,a,r,i,u=e.payload;e._wpnonce,a=function(e,n){t({success:e,result:n})},r=(n=u).challenge,(i=Object.assign({},n)).challenge=new Uint8Array(n.challenge),i.allowCredentials=i.allowCredentials.map(function(e){var t=Object.assign({},e);return t.id=new Uint8Array(e.id),t}),navigator.credentials.get({publicKey:i}).then(function(e){var t=[];new Uint8Array(e.rawId).forEach(function(e){t.push(e)});var n=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(e.response.clientDataJSON))),o=[];new Uint8Array(e.response.clientDataJSON).forEach(function(e){o.push(e)});var i=[];new Uint8Array(e.response.authenticatorData).forEach(function(e){i.push(e)});var u=[];new Uint8Array(e.response.signature).forEach(function(e){u.push(e)});var l={type:e.type,originalChallenge:r,rawId:t,response:{authenticatorData:i,clientData:n,clientDataJSONarray:o,signature:u}};a(!0,JSON.stringify(l))}).catch(function(e){console.log(e),"name"in e?(console.log(o(e)),console.log(e.name),console.log(e.message),"NotAllowedError"==e.name?a(!1,"not-allowed"):"AbortError"==e.name||"NS_ERROR_ABORT"==e.name?a(!1,"abort"):a(!1,e.toString())):a(!1,e.toString())})},sendRequest:function(e,t){var n=e.action,o=e.payload,r=e._wpnonce;a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:o,_wpnonce:r},success:t})},isWebauthnSupported:r}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},o=function(t,n){var o=n.action,r=n.payload,i=n._wpnonce,u=function(){var n=arguments.length>0&&void 0!==arguments[0]&&arguments[0],u=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!1),(0,a.default)(document).off("keydown"),(0,a.default)(t).off("blur"),n&&l!==u?((0,a.default)('<span class="spinner"></span>').insertAfter(t),(0,e.sendRequest)({action:o,payload:{md5id:r,label:u},_wpnonce:i},function(e){(0,a.default)(t).next(".spinner").remove()})):n||(0,a.default)(t).text(l)},l=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!0),(0,a.default)(document).on("keydown",function(e){13===e.which?(u(!0),e.preventDefault()):27===e.which&&u(!0)}),(0,a.default)(t).on("blur",function(e){return u(!0)}),(0,a.default)(t).focus(),document.execCommand("selectAll",!1,null)};(0,a.default)(document).on("click","#webauthn-register-key",function(t){t.preventDefault();var n=JSON.parse((0,a.default)(t.target).attr("data-create-options"));(0,e.register)(n,function(e){if(e.success){var t=(0,a.default)(e.html).appendTo("#webauthn-keys").find(".webauthn-label");o(t.get(0),JSON.parse(t.attr("data-action")))}else(0,a.default)('<span class="description">'.concat(e.info,"</span>")).insertAfter("#webauthn-register-key")})}),e.isWebauthnSupported?(0,a.default)(document).on("click",".webauthn-action",function(t){t.preventDefault();var n=(0,a.default)(t.target).closest(".webauthn-action"),r=JSON.parse(n.attr("data-action")),i=(0,a.default)(t.target).closest(".webauthn-key"),u=r.action,l=(r.payload,r._wpnonce);"webauthn-test-key"===r.action?(t.preventDefault(),(0,e.login)(r,function(t){console.log(t),t.success?(0,e.sendRequest)({action:u,payload:t.result,_wpnonce:l},function(e){e.success?n.find("[data-tested]").attr("data-tested","tested"):n.find("[data-tested]").attr("data-tested","fail")}):i.append('<div class="notice notice-inline notice-warning">Error: '.concat(t.result,"</div>"))})):"webauthn-delete-key"===r.action&&(t.preventDefault(),(0,e.sendRequest)(r,function(e){e.success&&i.remove()})),"webauthn-edit-key"===r.action&&"true"!==(0,a.default)(t.currentTarget).prop("contenteditable")&&(t.preventDefault(),o(t.currentTarget,r))}):((0,a.default)(".webauthn-unsupported").removeClass("hidden"),(0,a.default)(".webauthn-supported").addClass("hidden"))}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
!function(){var e={};(function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n};e={register:function(e,t){var n=e.action,r=e.payload,o=e._wpnonce;!function(e,t){(e=JSON.parse(e)).publicKey.attestation=void 0,e.publicKey.challenge=new Uint8Array(e.publicKey.challenge),e.publicKey.user.id=new Uint8Array(e.publicKey.user.id),navigator.credentials.create({publicKey:e.publicKey}).then(function(n){var a=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)));if(e.b64challenge!=a.challenge&&t(!1,"key returned something unexpected (1)"),"https://"+e.publicKey.rp.name!=a.origin)return t(!1,"key returned something unexpected (2)");if(!("type"in a))return t(!1,"key returned something unexpected (3)");if("webauthn.create"!=a.type)return t(!1,"key returned something unexpected (4)");var r=[];new Uint8Array(n.response.attestationObject).forEach(function(e){r.push(e)});var o=[];new Uint8Array(n.rawId).forEach(function(e){o.push(e)});var i={rawId:o,id:n.id,type:n.type,response:{attestationObject:r,clientDataJSON:JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)))}};t(!0,JSON.stringify(i))}).catch(function(e){"name"in e&&("AbortError"==e.name||"NS_ERROR_ABORT"==e.name)||"NotAllowedError"==e.name?t(!1,"abort"):t(!1,e.toString())})}(r,function(e,r){a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:r,_wpnonce:o},success:t})})},login:function(e,t){e.action;var n,a,r,o,i=e.payload;e._wpnonce,n=i,a=function(e,n){t({success:e,result:n})},r=JSON.parse(n),o=r.challenge,r.challenge=new Uint8Array(r.challenge),r.allowCredentials.forEach(function(e,t){r.allowCredentials[t].id=new Uint8Array(e.id)}),navigator.credentials.get({publicKey:r}).then(function(e){var t=[];new Uint8Array(e.rawId).forEach(function(e){t.push(e)});var n=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(e.response.clientDataJSON))),r=[];new Uint8Array(e.response.clientDataJSON).forEach(function(e){r.push(e)});var i=[];new Uint8Array(e.response.authenticatorData).forEach(function(e){i.push(e)});var l=[];new Uint8Array(e.response.signature).forEach(function(e){l.push(e)});var u={type:e.type,originalChallenge:o,rawId:t,response:{authenticatorData:i,clientData:n,clientDataJSONarray:r,signature:l}};a(!0,JSON.stringify(u))}).catch(function(e){"name"in e?"NotAllowedError"==e.name?a(!1,"not-allowed"):"AbortError"==e.name||"NS_ERROR_ABORT"==e.name?a(!1,"abort"):a(!1,e.toString()):a(!1,e.toString())})},sendRequest:function(e,t){var n=e.action,r=e.payload,o=e._wpnonce;a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:r,_wpnonce:o},success:t})}}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r=function(t,n){var r=n.action,o=n.payload,i=n._wpnonce,l=function(){var n=arguments.length>0&&void 0!==arguments[0]&&arguments[0],l=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!1),(0,a.default)(document).off("keydown"),(0,a.default)(t).off("blur"),n&&u!==l?((0,a.default)('<span class="spinner"></span>').insertAfter(t),(0,e.sendRequest)({action:r,payload:{md5id:o,label:l},_wpnonce:i},function(e){(0,a.default)(t).next(".spinner").remove()})):n||(0,a.default)(t).text(u)},u=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!0),(0,a.default)(document).on("keydown",function(e){13===e.which?(l(!0),e.preventDefault()):27===e.which&&l(!0)}),(0,a.default)(t).on("blur",function(e){return l(!0)}),(0,a.default)(t).focus(),document.execCommand("selectAll",!1,null)};(0,a.default)(document).on("click","#webauthn-register-key",function(t){t.preventDefault();var n=JSON.parse((0,a.default)(t.target).attr("data-create-options"));(0,e.register)(n,function(e){var t=(0,a.default)(e.html).appendTo("#webauthn-keys").find(".webauthn-label");r(t.get(0),JSON.parse(t.attr("data-action")))})}),(0,a.default)(document).on("click",".webauthn-action",function(t){var n=JSON.parse((0,a.default)(t.target).attr("data-action")),o=t.target;(0,a.default)(t.target).closest(".webauthn-key"),"webauthn-test-key"===n.action?(t.preventDefault(),(0,e.login)(n,function(e){console.log(e),(0,a.default)(o).append('<span class="dashicons dashicons-yes-alt"></span>')})):"webauthn-delete-key"===n.action&&(t.preventDefault(),(0,e.sendRequest)(n,function(e){e.success&&(0,a.default)(o).closest(".webauthn-key").remove()})),"webauthn-edit-key"===n.action&&"true"!==(0,a.default)(t.currentTarget).prop("contenteditable")&&(t.preventDefault(),r(t.currentTarget,n))})}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
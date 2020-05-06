!function(){var e={};(function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n};e={register:function(e,t){var n=e.action,r=e.payload,o=e._wpnonce;!function(e,t){var n=Object.assign({},e.publicKey);n.attestation=void 0,n.challenge=new Uint8Array(n.challenge),n.user.id=new Uint8Array(n.user.id),navigator.credentials.create({publicKey:n}).then(function(n){var a=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)));if(e.b64challenge!==a.challenge&&t(!1,"key returned something unexpected (1)"),"https://"+e.publicKey.rp.name!=a.origin)return t(!1,"key returned something unexpected (2)");if(!("type"in a))return t(!1,"key returned something unexpected (3)");if("webauthn.create"!=a.type)return t(!1,"key returned something unexpected (4)");var r=[];new Uint8Array(n.response.attestationObject).forEach(function(e){r.push(e)});var o=[];new Uint8Array(n.rawId).forEach(function(e){o.push(e)});var i={rawId:o,id:n.id,type:n.type,response:{attestationObject:r,clientDataJSON:JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)))}};t(!0,JSON.stringify(i))}).catch(function(e){"name"in e&&("AbortError"==e.name||"NS_ERROR_ABORT"==e.name)||"NotAllowedError"==e.name?t(!1,"abort"):t(!1,e.toString())})}(r,function(e,r){a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:r,_wpnonce:o},success:t})})},login:function(e,t){e.action;var n,a,r,o,i=e.payload;e._wpnonce,a=function(e,n){t({success:e,result:n})},r=(n=i).challenge,(o=Object.assign({},n)).challenge=new Uint8Array(n.challenge),o.allowCredentials=o.allowCredentials.map(function(e){var t=Object.assign({},e);return t.id=new Uint8Array(e.id),t}),navigator.credentials.get({publicKey:o}).then(function(e){var t=[];new Uint8Array(e.rawId).forEach(function(e){t.push(e)});var n=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(e.response.clientDataJSON))),o=[];new Uint8Array(e.response.clientDataJSON).forEach(function(e){o.push(e)});var i=[];new Uint8Array(e.response.authenticatorData).forEach(function(e){i.push(e)});var u=[];new Uint8Array(e.response.signature).forEach(function(e){u.push(e)});var l={type:e.type,originalChallenge:r,rawId:t,response:{authenticatorData:i,clientData:n,clientDataJSONarray:o,signature:u}};a(!0,JSON.stringify(l))}).catch(function(e){"name"in e?"NotAllowedError"==e.name?a(!1,"not-allowed"):"AbortError"==e.name||"NS_ERROR_ABORT"==e.name?a(!1,"abort"):a(!1,e.toString()):a(!1,e.toString())})},sendRequest:function(e,t){var n=e.action,r=e.payload,o=e._wpnonce;a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:r,_wpnonce:o},success:t})}}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r=function(t,n){var r=n.action,o=n.payload,i=n._wpnonce,u=function(){var n=arguments.length>0&&void 0!==arguments[0]&&arguments[0],u=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!1),(0,a.default)(document).off("keydown"),(0,a.default)(t).off("blur"),n&&l!==u?((0,a.default)('<span class="spinner"></span>').insertAfter(t),(0,e.sendRequest)({action:r,payload:{md5id:o,label:u},_wpnonce:i},function(e){(0,a.default)(t).next(".spinner").remove()})):n||(0,a.default)(t).text(l)},l=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!0),(0,a.default)(document).on("keydown",function(e){13===e.which?(u(!0),e.preventDefault()):27===e.which&&u(!0)}),(0,a.default)(t).on("blur",function(e){return u(!0)}),(0,a.default)(t).focus(),document.execCommand("selectAll",!1,null)};(0,a.default)(document).on("click","#webauthn-register-key",function(t){t.preventDefault();var n=JSON.parse((0,a.default)(t.target).attr("data-create-options"));(0,e.register)(n,function(e){var t=(0,a.default)(e.html).appendTo("#webauthn-keys").find(".webauthn-label");r(t.get(0),JSON.parse(t.attr("data-action")))})}),(0,a.default)(document).on("click",".webauthn-action",function(t){t.preventDefault();var n=(0,a.default)(t.target).closest(".webauthn-action"),o=JSON.parse(n.attr("data-action")),i=(0,a.default)(t.target).closest(".webauthn-key"),u=o.action,l=(o.payload,o._wpnonce);"webauthn-test-key"===o.action?(t.preventDefault(),(0,e.login)(o,function(t){console.log(t),(0,e.sendRequest)({action:u,payload:t.result,_wpnonce:l},function(e){e.success?n.find("[data-tested]").attr("data-tested","tested"):n.find("[data-tested]").attr("data-tested","fail")})})):"webauthn-delete-key"===o.action&&(t.preventDefault(),(0,e.sendRequest)(o,function(e){e.success&&i.remove()})),"webauthn-edit-key"===o.action&&"true"!==(0,a.default)(t.currentTarget).prop("contenteditable")&&(t.preventDefault(),r(t.currentTarget,o))})}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
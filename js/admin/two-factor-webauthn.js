!function(){var e={};(function(t){(function(){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r="credentials"in navigator;e={register:function(e,t){var n=e.action,r=e.user_id,i=e.payload,s=e._wpnonce;!function(e,t){var n=Object.assign({},e.publicKey);n.attestation=void 0,n.challenge=new Uint8Array(n.challenge),n.user.id=new Uint8Array(n.user.id),navigator.credentials.create({publicKey:n}).then(function(n){var a=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)));if(e.b64challenge!==a.challenge&&t(!1,"key returned something unexpected (1)"),!("type"in a))return t(!1,"key returned something unexpected (3)");if("webauthn.create"!=a.type)return t(!1,"key returned something unexpected (4)");var r=[];new Uint8Array(n.response.attestationObject).forEach(function(e){r.push(e)});var i=[];new Uint8Array(n.rawId).forEach(function(e){i.push(e)});var s={rawId:i,id:n.id,type:n.type,response:{attestationObject:r,clientDataJSON:JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)))}};t(!0,JSON.stringify(s))}).catch(function(e){t(!1,"name"in e?e.name+": "+e.message:e.toString())})}(i,function(e,i){e?a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:i,user_id:r,_wpnonce:s},success:t}):t({success:!1,message:i})})},login:function(e,t){e.action;var n=e.payload;e._wpnonce,function(e,t){var n=e.challenge,a=Object.assign({},e);a.challenge=new Uint8Array(e.challenge),a.allowCredentials=a.allowCredentials.map(function(e){var t=Object.assign({},e);return t.id=new Uint8Array(e.id),t}),navigator.credentials.get({publicKey:a}).then(function(e){var a=[];new Uint8Array(e.rawId).forEach(function(e){a.push(e)});var r=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(e.response.clientDataJSON))),i=[];new Uint8Array(e.response.clientDataJSON).forEach(function(e){i.push(e)});var s=[];new Uint8Array(e.response.authenticatorData).forEach(function(e){s.push(e)});var o=[];new Uint8Array(e.response.signature).forEach(function(e){o.push(e)});var u={type:e.type,originalChallenge:n,rawId:a,response:{authenticatorData:s,clientData:r,clientDataJSONarray:i,signature:o}};t(!0,JSON.stringify(u))}).catch(function(e){console.log(e),t(!1,"name"in e?e.name+": "+e.message:e.toString())})}(n,function(e,n){t(e?{success:!0,result:n}:{success:!1,message:n})})},sendRequest:function(e,t){a.default.ajax({url:wp.ajax.settings.url,method:"post",data:e,success:t})},isWebauthnSupported:r}}).call(this)}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(t){(function(){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r=function(t,n){var r=n.action,i=n.payload,s=n._wpnonce,o=n.user_id,u=function(){var n=arguments.length>0&&void 0!==arguments[0]&&arguments[0],u=(0,a.default)(t).text();(0,a.default)(t).text(u),(0,a.default)(t).prop("contenteditable",!1),(0,a.default)(document).off("keydown"),(0,a.default)(t).off("blur"),n&&d!==u?((0,a.default)(t).addClass("busy"),(0,e.sendRequest)({action:r,payload:{md5id:i,label:u},user_id:o,_wpnonce:s},function(e){(0,a.default)(t).removeClass("busy")})):n||(0,a.default)(t).text(d)},d=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!0),(0,a.default)(document).on("keydown",function(e){13===e.which?(u(!0),e.preventDefault()):27===e.which&&u(!0)}),(0,a.default)(t).on("blur",function(e){return u(!0)}).on("paste",function(e){e.preventDefault();var t=(e.originalEvent||e).clipboardData.getData("text/plain");document.execCommand("insertHTML",!1,t)}),(0,a.default)(t).focus(),document.execCommand("selectAll",!1,null)};(0,a.default)(document).on("click","#webauthn-register-key",function(t){t.preventDefault(),(0,a.default)(t.target).next(".webauthn-error").remove();var n=(0,a.default)(t.target).addClass("busy"),i=JSON.parse((0,a.default)(t.target).attr("data-create-options"));(0,e.register)(i,function(e){if(n.removeClass("busy"),e.success){var t=(0,a.default)(e.html).appendTo("#webauthn-keys").find(".webauthn-label");r(t.get(0),JSON.parse(t.attr("data-action")))}else{var i;i=e.message?e.message:e.data&&e.data[0]&&e.data[0].message?e.data[0].message:JSON.stringify(e),(0,a.default)('<span class="webauthn-error description">'.concat(i,"</span>")).insertAfter("#webauthn-register-key")}})}),e.isWebauthnSupported?(0,a.default)(document).on("click",".webauthn-action",function(t){t.preventDefault();var n=(0,a.default)(t.target).closest(".webauthn-action"),i=JSON.parse(n.attr("data-action")),s=(0,a.default)(t.target).closest(".webauthn-key"),o=i.action,u=i.user_id,d=(i.payload,i._wpnonce);"webauthn-test-key"===o?(t.preventDefault(),s.find(".notice").remove(),n.addClass("busy"),(0,e.login)(i,function(t){if(!t.success)return s.append('<div class="notice notice-inline notice-warning">'.concat(t.message,"</div>")),void n.removeClass("busy");(0,e.sendRequest)({action:o,user_id:u,payload:t.result,_wpnonce:d},function(e){e.success?n.find("[data-tested]").attr("data-tested","tested"):(n.find("[data-tested]").attr("data-tested","fail"),s.append('<div class="notice notice-inline notice-error">'.concat(e.message,"</div>"))),n.removeClass("busy")})})):"webauthn-delete-key"===o&&(s.addClass("busy"),t.preventDefault(),(0,e.sendRequest)(i,function(e){s.removeClass("busy"),e.success?s.remove():s.append('<div class="notice notice-inline notice-error">'.concat(e.data[0].message,"</div>"))})),"webauthn-edit-key"===i.action&&"true"!==(0,a.default)(t.currentTarget).prop("contenteditable")&&(t.preventDefault(),r(t.currentTarget,i))}):((0,a.default)(".webauthn-unsupported").removeClass("hidden"),(0,a.default)(".webauthn-supported").addClass("hidden"))}).call(this)}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
!function(){var e={};(function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r="credentials"in navigator;e={register:function(e,t){var n=e.action,r=e.user_id,s=e.payload,i=e._wpnonce;!function(e,t){var n=Object.assign({},e.publicKey);n.attestation=void 0,n.challenge=new Uint8Array(n.challenge),n.user.id=new Uint8Array(n.user.id),navigator.credentials.create({publicKey:n}).then(function(n){var a=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)));if(e.b64challenge!==a.challenge&&t(!1,"key returned something unexpected (1)"),!("type"in a))return t(!1,"key returned something unexpected (3)");if("webauthn.create"!=a.type)return t(!1,"key returned something unexpected (4)");var r=[];new Uint8Array(n.response.attestationObject).forEach(function(e){r.push(e)});var s=[];new Uint8Array(n.rawId).forEach(function(e){s.push(e)});var i={rawId:s,id:n.id,type:n.type,response:{attestationObject:r,clientDataJSON:JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON)))}};t(!0,JSON.stringify(i))}).catch(function(e){t(!1,"name"in e?e.name+": "+e.message:e.toString())})}(s,function(e,s){e?a.default.ajax({url:wp.ajax.settings.url,method:"post",data:{action:n,payload:s,user_id:r,_wpnonce:i},success:t}):t({success:!1,message:s})})},login:function(e,t){e.action;var n=e.payload;e._wpnonce,function(e,t){var n=e.challenge,a=Object.assign({},e);a.challenge=new Uint8Array(e.challenge),a.allowCredentials=a.allowCredentials.map(function(e){var t=Object.assign({},e);return t.id=new Uint8Array(e.id),t}),navigator.credentials.get({publicKey:a}).then(function(e){var a=[];new Uint8Array(e.rawId).forEach(function(e){a.push(e)});var r=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(e.response.clientDataJSON))),s=[];new Uint8Array(e.response.clientDataJSON).forEach(function(e){s.push(e)});var i=[];new Uint8Array(e.response.authenticatorData).forEach(function(e){i.push(e)});var o=[];new Uint8Array(e.response.signature).forEach(function(e){o.push(e)});var u={type:e.type,originalChallenge:n,rawId:a,response:{authenticatorData:i,clientData:r,clientDataJSONarray:s,signature:o}};t(!0,JSON.stringify(u))}).catch(function(e){console.log(e),t(!1,"name"in e?e.name+": "+e.message:e.toString())})}(n,function(e,n){t(e?{success:!0,result:n}:{success:!1,message:n})})},sendRequest:function(e,t){a.default.ajax({url:wp.ajax.settings.url,method:"post",data:e,success:t})},isWebauthnSupported:r}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(t){"use strict";var n,a=(n="undefined"!=typeof window?window.jQuery:void 0!==t?t.jQuery:null)&&n.__esModule?n:{default:n},r=function(t,n){var r=n.action,s=n.payload,i=n._wpnonce,o=function(){var n=arguments.length>0&&void 0!==arguments[0]&&arguments[0],o=(0,a.default)(t).text();(0,a.default)(t).text(o),(0,a.default)(t).prop("contenteditable",!1),(0,a.default)(document).off("keydown"),(0,a.default)(t).off("blur"),n&&u!==o?((0,a.default)(t).addClass("busy"),(0,e.sendRequest)({action:r,payload:{md5id:s,label:o},_wpnonce:i},function(e){(0,a.default)(t).removeClass("busy")})):n||(0,a.default)(t).text(u)},u=(0,a.default)(t).text();(0,a.default)(t).prop("contenteditable",!0),(0,a.default)(document).on("keydown",function(e){13===e.which?(o(!0),e.preventDefault()):27===e.which&&o(!0)}),(0,a.default)(t).on("blur",function(e){return o(!0)}).on("paste",function(e){e.preventDefault();var t=(e.originalEvent||e).clipboardData.getData("text/plain");document.execCommand("insertHTML",!1,t)}),(0,a.default)(t).focus(),document.execCommand("selectAll",!1,null)};(0,a.default)(document).on("click","#webauthn-register-key",function(t){t.preventDefault(),(0,a.default)(t.target).next(".webauthn-error").remove();var n=(0,a.default)(t.target).addClass("busy"),s=JSON.parse((0,a.default)(t.target).attr("data-create-options"));(0,e.register)(s,function(e){if(n.removeClass("busy"),e.success){var t=(0,a.default)(e.html).appendTo("#webauthn-keys").find(".webauthn-label");r(t.get(0),JSON.parse(t.attr("data-action")))}else{var s;s=e.message?e.message:e.data&&e.data[0]&&e.data[0].message?e.data[0].message:JSON.stringify(e),(0,a.default)('<span class="webauthn-error description">'.concat(s,"</span>")).insertAfter("#webauthn-register-key")}})}),e.isWebauthnSupported?(0,a.default)(document).on("click",".webauthn-action",function(t){t.preventDefault();var n=(0,a.default)(t.target).closest(".webauthn-action"),s=JSON.parse(n.attr("data-action")),i=(0,a.default)(t.target).closest(".webauthn-key"),o=s.action,u=s.user_id,d=(s.payload,s._wpnonce);"webauthn-test-key"===o?(t.preventDefault(),i.find(".notice").remove(),n.addClass("busy"),(0,e.login)(s,function(t){if(!t.success)return i.append('<div class="notice notice-inline notice-warning">'.concat(t.message,"</div>")),void n.removeClass("busy");console.log({action:o,user_id:u,payload:t.result,_wpnonce:d}),(0,e.sendRequest)({action:o,user_id:u,payload:t.result,_wpnonce:d},function(e){e.success?n.find("[data-tested]").attr("data-tested","tested"):(n.find("[data-tested]").attr("data-tested","fail"),i.append('<div class="notice notice-inline notice-error">'.concat(e.message,"</div>"))),n.removeClass("busy")})})):"webauthn-delete-key"===o&&(i.addClass("busy"),t.preventDefault(),(0,e.sendRequest)(s,function(e){i.removeClass("busy"),e.success?i.remove():i.append('<div class="notice notice-inline notice-error">'.concat(e.data[0].message,"</div>"))})),"webauthn-edit-key"===s.action&&"true"!==(0,a.default)(t.currentTarget).prop("contenteditable")&&(t.preventDefault(),r(t.currentTarget,s))}):((0,a.default)(".webauthn-unsupported").removeClass("hidden"),(0,a.default)(".webauthn-supported").addClass("hidden"))}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
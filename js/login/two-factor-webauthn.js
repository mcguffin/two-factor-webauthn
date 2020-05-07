!function(){var n={};(function(e){"use strict";(t="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&t.__esModule;var t,a="credentials"in navigator;n={login:function(n,e){n.action;var t=n.payload;n._wpnonce,function(n,e){var t=n.challenge,a=Object.assign({},n);a.challenge=new Uint8Array(n.challenge),a.allowCredentials=a.allowCredentials.map(function(n){var e=Object.assign({},n);return e.id=new Uint8Array(n.id),e}),navigator.credentials.get({publicKey:a}).then(function(n){var a=[];new Uint8Array(n.rawId).forEach(function(n){a.push(n)});var i=JSON.parse(String.fromCharCode.apply(null,new Uint8Array(n.response.clientDataJSON))),r=[];new Uint8Array(n.response.clientDataJSON).forEach(function(n){r.push(n)});var o=[];new Uint8Array(n.response.authenticatorData).forEach(function(n){o.push(n)});var u=[];new Uint8Array(n.response.signature).forEach(function(n){u.push(n)});var l={type:n.type,originalChallenge:t,rawId:a,response:{authenticatorData:o,clientData:i,clientDataJSONarray:r,signature:u}};e(!0,JSON.stringify(l))}).catch(function(n){console.log(n),e(!1,"name"in n?n.name+": "+n.message:n.toString())})}(t,function(n,t){e(n?{success:!0,result:t}:{success:!1,message:t})})},isWebauthnSupported:a}}).call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{}),function(e){"use strict";var t,a=(t="undefined"!=typeof window?window.jQuery:void 0!==e?e.jQuery:null)&&t.__esModule?t:{default:t},i=function(){(0,a.default)(".webauthn-retry").removeClass("visible"),(0,n.login)(window.webauthnL10n,function(n){n.success?((0,a.default)("#webauthn_response").val(n.result),(0,a.default)("#loginform").submit()):(0,a.default)(".webauthn-retry").addClass("visible")})};window.webauthnL10n||console.error("webauthL10n is not defined"),n.isWebauthnSupported?(0,a.default)(document).ready(function(){return i()}).on("click",".webauthn-retry-link",function(){return i()}):(0,a.default)(".webauthn-unsupported").addClass("visible")}.call(this,"undefined"!=typeof global?global:"undefined"!=typeof self?self:"undefined"!=typeof window?window:{})}();
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2stZmxhdC9fcHJlbHVkZSIsInNyYy9qcy9saWIvZGF2aWRlYXJsLXdlYmF1dGhuLmpzIiwic3JjL2pzL2xvZ2luL3R3by1mYWN0b3Itd2ViYXV0aG4vaW5kZXguanMiXSwibmFtZXMiOlsiXyRkYXZpZGVhcmxXZWJhdXRobl8xIiwib2JqIiwid2luZG93IiwialF1ZXJ5IiwiZ2xvYmFsIiwiX19lc01vZHVsZSIsImlzV2ViYXV0aG5TdXBwb3J0ZWQiLCJuYXZpZ2F0b3IiLCJsb2dpbiIsIm9wdHMiLCJjYWxsYmFjayIsImFjdGlvbiIsInBheWxvYWQiLCJfd3Bub25jZSIsInB1YktleUF1dGgiLCJvcmlnaW5hbENoYWxsZW5nZSIsImNoYWxsZW5nZSIsInBrIiwiT2JqZWN0IiwiYXNzaWduIiwiVWludDhBcnJheSIsImFsbG93Q3JlZGVudGlhbHMiLCJtYXAiLCJrIiwicmV0IiwiaWQiLCJjcmVkZW50aWFscyIsImdldCIsInB1YmxpY0tleSIsInRoZW4iLCJhQXNzZXJ0aW9uIiwiaWRhIiwicmF3SWQiLCJmb3JFYWNoIiwidiIsInB1c2giLCJjZCIsIkpTT04iLCJwYXJzZSIsIlN0cmluZyIsImZyb21DaGFyQ29kZSIsImFwcGx5IiwicmVzcG9uc2UiLCJjbGllbnREYXRhSlNPTiIsImNkYSIsImFkIiwiYXV0aGVudGljYXRvckRhdGEiLCJzaWciLCJzaWduYXR1cmUiLCJpbmZvIiwidHlwZSIsImNsaWVudERhdGEiLCJjbGllbnREYXRhSlNPTmFycmF5Iiwic3RyaW5naWZ5IiwiY2F0Y2giLCJlcnIiLCJjb25zb2xlIiwibG9nIiwibmFtZSIsIm1lc3NhZ2UiLCJ0b1N0cmluZyIsInN1Y2Nlc3MiLCJyZXN1bHQiLCJfanF1ZXJ5IiwiZGVmYXVsdCIsImF1dGgiLCJyZW1vdmVDbGFzcyIsIndlYmF1dGhuTDEwbiIsInZhbCIsInN1Ym1pdCIsImFkZENsYXNzIiwiZXJyb3IiLCJkb2N1bWVudCIsInJlYWR5Iiwi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QkFBeUJNLFNBQVMsNEhGL0JyQyIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbigpe1xuIiwiaW1wb3J0ICQgZnJvbSAnanF1ZXJ5J1xuXG5cblxuXG4vKipcbiAqXHRTdG9sZW4gZnJvbSBodHRwczovL2dpdGh1Yi5jb20vZGF2aWRlYXJsL3dlYmF1dGhuXG4gKi9cbmZ1bmN0aW9uIHdlYmF1dGhuQXV0aGVudGljYXRlKCBwdWJLZXlBdXRoLCBjYWxsYmFjayApIHtcblxuXHRjb25zdCBvcmlnaW5hbENoYWxsZW5nZSA9IHB1YktleUF1dGguY2hhbGxlbmdlO1xuXHRjb25zdCBwayA9IE9iamVjdC5hc3NpZ24oIHt9LCBwdWJLZXlBdXRoIClcblxuXHRway5jaGFsbGVuZ2UgPSBuZXcgVWludDhBcnJheSggcHViS2V5QXV0aC5jaGFsbGVuZ2UgKVxuXHRway5hbGxvd0NyZWRlbnRpYWxzID0gcGsuYWxsb3dDcmVkZW50aWFscy5tYXAoIGsgPT4ge1xuXHRcdGxldCByZXQgPSBPYmplY3QuYXNzaWduKCB7fSwgayApXG5cdFx0cmV0LmlkID0gbmV3IFVpbnQ4QXJyYXkoay5pZCk7XG5cdFx0cmV0dXJuIHJldFxuXHR9IClcblxuXHQvKiBhc2sgdGhlIGJyb3dzZXIgdG8gcHJvbXB0IHRoZSB1c2VyICovXG5cdG5hdmlnYXRvci5jcmVkZW50aWFscy5nZXQoIHsgcHVibGljS2V5OiBwayB9IClcblx0XHQudGhlbiggYUFzc2VydGlvbiA9PiB7XG5cdFx0XHQvLyBjb25zb2xlLmxvZyhcIkNyZWRlbnRpYWxzLkdldCByZXNwb25zZTogXCIsIGFBc3NlcnRpb24pO1xuXHRcdFx0dmFyIGlkYSA9IFtdO1xuXHRcdFx0KG5ldyBVaW50OEFycmF5KGFBc3NlcnRpb24ucmF3SWQpKS5mb3JFYWNoKGZ1bmN0aW9uKHYpeyBpZGEucHVzaCh2KTsgfSk7XG5cdFx0XHR2YXIgY2QgPSBKU09OLnBhcnNlKFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCxcblx0XHRcdFx0XHRcdFx0XHRcdFx0XHRcdFx0XHQgIG5ldyBVaW50OEFycmF5KGFBc3NlcnRpb24ucmVzcG9uc2UuY2xpZW50RGF0YUpTT04pKSk7XG5cdFx0XHR2YXIgY2RhID0gW107XG5cdFx0XHQobmV3IFVpbnQ4QXJyYXkoYUFzc2VydGlvbi5yZXNwb25zZS5jbGllbnREYXRhSlNPTikpLmZvckVhY2goZnVuY3Rpb24odil7IGNkYS5wdXNoKHYpOyB9KTtcblx0XHRcdHZhciBhZCA9IFtdO1xuXHRcdFx0KG5ldyBVaW50OEFycmF5KGFBc3NlcnRpb24ucmVzcG9uc2UuYXV0aGVudGljYXRvckRhdGEpKS5mb3JFYWNoKGZ1bmN0aW9uKHYpeyBhZC5wdXNoKHYpOyB9KTtcblx0XHRcdHZhciBzaWcgPSBbXTtcblx0XHRcdChuZXcgVWludDhBcnJheShhQXNzZXJ0aW9uLnJlc3BvbnNlLnNpZ25hdHVyZSkpLmZvckVhY2goZnVuY3Rpb24odil7IHNpZy5wdXNoKHYpOyB9KTtcblx0XHRcdHZhciBpbmZvID0ge1xuXHRcdFx0XHR0eXBlOiBhQXNzZXJ0aW9uLnR5cGUsXG5cdFx0XHRcdG9yaWdpbmFsQ2hhbGxlbmdlOiBvcmlnaW5hbENoYWxsZW5nZSxcblx0XHRcdFx0cmF3SWQ6IGlkYSxcblx0XHRcdFx0cmVzcG9uc2U6IHtcblx0XHRcdFx0XHRhdXRoZW50aWNhdG9yRGF0YTogYWQsXG5cdFx0XHRcdFx0Y2xpZW50RGF0YTogY2QsXG5cdFx0XHRcdFx0Y2xpZW50RGF0YUpTT05hcnJheTogY2RhLFxuXHRcdFx0XHRcdHNpZ25hdHVyZTogc2lnXG5cdFx0XHRcdH1cblx0XHRcdH07XG5cdFx0XHRjYWxsYmFjayggdHJ1ZSwgSlNPTi5zdHJpbmdpZnkoIGluZm8gKSApO1xuXHRcdH0pXG5cdFx0LmNhdGNoKCBlcnIgPT4ge1xuXHRcdFx0Y29uc29sZS5sb2coZXJyKVxuXHRcdFx0Lypcblx0XHRcdEZGIG1hYzpcblx0XHRcdEludmFsaWRTdGF0ZUVycm9yOiBrZXkgbm90IGZvdW5kXG5cdFx0XHRBYm9ydEVycm9yOiB1c2VyIGFib3J0ZWQgb3IgZGVuaWVkXG5cdFx0XHROb3RBbGxvd2VkRXJyb3I6ID9cblx0XHRcdFx0VGhlIHJlcXVlc3QgaXMgbm90IGFsbG93ZWQgYnkgdGhlIHVzZXIgYWdlbnQgb3IgdGhlIHBsYXRmb3JtIGluIHRoZSBjdXJyZW50IGNvbnRleHQsIHBvc3NpYmx5IGJlY2F1c2UgdGhlIHVzZXIgZGVuaWVkIHBlcm1pc3Npb24uXG5cblx0XHRcdENocm9tZSBtYWM6XG5cdFx0XHROb3RBbGxvd2VkRXJyb3I6IHVzZXIgYWJvcnRlZCBvciBkZW5pZWRcblxuXHRcdFx0U2FmYXJpIG1hYzpcblx0XHRcdE5vdEFsbG93ZWRFcnJvcjogdXNlciBhYm9ydGVkIG9yIGRlbmllZFxuXG5cdFx0XHRFZGdlIHdpbjEwOlxuXHRcdFx0VW5rbm93bkVycm9yOiB3cm9uZyBrZXkuLi4/XG5cdFx0XHROb3RBbGxvd2VkRXJyb3I6IHVzZXIgYWJvcnRlZCBvciBkZW5pZWRcblxuXHRcdFx0RkYgd2luOlxuXHRcdFx0Tm90QWxsb3dlZEVycm9yOiB1c2VyIGFib3J0ZWQgb3IgZGVuaWVkXG5cdFx0XHRcdERPTUV4Y2VwdGlvbjogXCJUaGUgcmVxdWVzdCBpcyBub3QgYWxsb3dlZCBieSB0aGUgdXNlciBhZ2VudCBvciB0aGUgcGxhdGZvcm0gaW4gdGhlIGN1cnJlbnQgY29udGV4dCwgcG9zc2libHkgYmVjYXVzZSB0aGUgdXNlciBkZW5pZWQgcGVybWlzc2lvbi5cIlxuXG5cdFx0XHQqL1xuXHRcdFx0aWYgKCBcIm5hbWVcIiBpbiBlcnIgKSB7XG5cdFx0XHRcdGNhbGxiYWNrKCBmYWxzZSwgZXJyLm5hbWUgKyAnOiAnICsgZXJyLm1lc3NhZ2UgKTtcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdGNhbGxiYWNrKCBmYWxzZSwgZXJyLnRvU3RyaW5nKCkgKTtcblx0XHRcdH1cblx0XHR9KTtcbn1cblxuLyoqXG4gKlx0U3RvbGVuIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL2RhdmlkZWFybC93ZWJhdXRoblxuICovXG5mdW5jdGlvbiB3ZWJhdXRoblJlZ2lzdGVyKCBrZXksIGNhbGxiYWNrICl7XG5cblx0bGV0IHB1YmxpY0tleSA9IE9iamVjdC5hc3NpZ24oIHt9LCBrZXkucHVibGljS2V5ICk7XG5cblx0cHVibGljS2V5LmF0dGVzdGF0aW9uID0gdW5kZWZpbmVkO1xuXHRwdWJsaWNLZXkuY2hhbGxlbmdlID0gbmV3IFVpbnQ4QXJyYXkoIHB1YmxpY0tleS5jaGFsbGVuZ2UgKTsgLy8gY29udmVydCB0eXBlIGZvciB1c2UgYnkga2V5XG5cdHB1YmxpY0tleS51c2VyLmlkID0gbmV3IFVpbnQ4QXJyYXkoIHB1YmxpY0tleS51c2VyLmlkICk7XG5cblx0Ly8gY29uc29sZS5sb2coa2V5KTtcblx0bmF2aWdhdG9yLmNyZWRlbnRpYWxzLmNyZWF0ZSggeyBwdWJsaWNLZXkgfSApXG5cdFx0LnRoZW4oZnVuY3Rpb24gKGFOZXdDcmVkZW50aWFsSW5mbykge1xuXHRcdFx0Ly8gY29uc29sZS5sb2coXCJDcmVkZW50aWFscy5DcmVhdGUgcmVzcG9uc2U6IFwiLCBhTmV3Q3JlZGVudGlhbEluZm8pO1xuXHRcdFx0dmFyIGNkID0gSlNPTi5wYXJzZShTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIG5ldyBVaW50OEFycmF5KGFOZXdDcmVkZW50aWFsSW5mby5yZXNwb25zZS5jbGllbnREYXRhSlNPTikpKTtcblx0XHRcdGlmICgga2V5LmI2NGNoYWxsZW5nZSAhPT0gY2QuY2hhbGxlbmdlICkge1xuXHRcdFx0XHRjYWxsYmFjayhmYWxzZSwgJ2tleSByZXR1cm5lZCBzb21ldGhpbmcgdW5leHBlY3RlZCAoMSknKTtcblx0XHRcdH1cblx0XHRcdGlmICgnaHR0cHM6Ly8nK2tleS5wdWJsaWNLZXkucnAubmFtZSAhPSBjZC5vcmlnaW4pIHtcblx0XHRcdFx0cmV0dXJuIGNhbGxiYWNrKGZhbHNlLCAna2V5IHJldHVybmVkIHNvbWV0aGluZyB1bmV4cGVjdGVkICgyKScpO1xuXHRcdFx0fVxuXHRcdFx0aWYgKCEgKCd0eXBlJyBpbiBjZCkpIHtcblx0XHRcdFx0cmV0dXJuIGNhbGxiYWNrKGZhbHNlLCAna2V5IHJldHVybmVkIHNvbWV0aGluZyB1bmV4cGVjdGVkICgzKScpO1xuXHRcdFx0fVxuXHRcdFx0aWYgKGNkLnR5cGUgIT0gJ3dlYmF1dGhuLmNyZWF0ZScpIHtcblx0XHRcdFx0cmV0dXJuIGNhbGxiYWNrKGZhbHNlLCAna2V5IHJldHVybmVkIHNvbWV0aGluZyB1bmV4cGVjdGVkICg0KScpO1xuXHRcdFx0fVxuXG5cdFx0XHR2YXIgYW8gPSBbXTtcblx0XHRcdChuZXcgVWludDhBcnJheShhTmV3Q3JlZGVudGlhbEluZm8ucmVzcG9uc2UuYXR0ZXN0YXRpb25PYmplY3QpKS5mb3JFYWNoKGZ1bmN0aW9uKHYpe1xuXHRcdFx0XHRhby5wdXNoKHYpO1xuXHRcdFx0fSk7XG5cdFx0XHR2YXIgcmF3SWQgPSBbXTtcblx0XHRcdChuZXcgVWludDhBcnJheShhTmV3Q3JlZGVudGlhbEluZm8ucmF3SWQpKS5mb3JFYWNoKGZ1bmN0aW9uKHYpe1xuXHRcdFx0XHRyYXdJZC5wdXNoKHYpO1xuXHRcdFx0fSk7XG5cdFx0XHR2YXIgaW5mbyA9IHtcblx0XHRcdFx0cmF3SWQ6IHJhd0lkLFxuXHRcdFx0XHRpZDogYU5ld0NyZWRlbnRpYWxJbmZvLmlkLFxuXHRcdFx0XHR0eXBlOiBhTmV3Q3JlZGVudGlhbEluZm8udHlwZSxcblx0XHRcdFx0cmVzcG9uc2U6IHtcblx0XHRcdFx0XHRhdHRlc3RhdGlvbk9iamVjdDogYW8sXG5cdFx0XHRcdFx0Y2xpZW50RGF0YUpTT046XG5cdFx0XHRcdFx0ICBKU09OLnBhcnNlKFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgbmV3IFVpbnQ4QXJyYXkoYU5ld0NyZWRlbnRpYWxJbmZvLnJlc3BvbnNlLmNsaWVudERhdGFKU09OKSkpXG5cdFx0XHRcdH1cblx0XHRcdH07XG5cdFx0XHRjYWxsYmFjayh0cnVlLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XG5cdFx0fSlcblx0XHQuY2F0Y2goIGVyciA9PiB7XG5cdFx0XHRpZiAoIFwibmFtZVwiIGluIGVyciApIHtcblx0XHRcdFx0Y2FsbGJhY2soIGZhbHNlLCBlcnIubmFtZSArICc6ICcgKyBlcnIubWVzc2FnZSApO1xuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0Y2FsbGJhY2soIGZhbHNlLCBlcnIudG9TdHJpbmcoKSApO1xuXHRcdFx0fVxuXHRcdH0pO1xufVxuXG4vKipcbiAqXHRAcGFyYW0gQXJyYXlCdWZmZXIgYXJyYXlCdWZcbiAqXHRAcmV0dXJuIEFycmF5XG4gKi9cbmNvbnN0IGJ1ZmZlcjJBcnJheSA9IGFycmF5QnVmID0+IFsgLi4uIChuZXcgVWludDhBcnJheSggYXJyYXlCdWYgKSkgXTtcblxuY29uc3QgcmVnaXN0ZXIgPSAoIG9wdHMsIGNhbGxiYWNrICkgPT4ge1xuXG5cdGNvbnN0IHsgYWN0aW9uLCBwYXlsb2FkLCBfd3Bub25jZSB9ID0gb3B0cztcblxuXHR3ZWJhdXRoblJlZ2lzdGVyKCBwYXlsb2FkLCAoc3VjY2VzcyxpbmZvKSA9PiB7XG5cdFx0aWYgKCBzdWNjZXNzICkge1xuXHRcdFx0JC5hamF4KHtcblx0XHRcdFx0dXJsOiB3cC5hamF4LnNldHRpbmdzLnVybCxcblx0XHRcdFx0bWV0aG9kOiAncG9zdCcsXG5cdFx0XHRcdGRhdGE6IHtcblx0XHRcdFx0XHRhY3Rpb246IGFjdGlvbixcblx0XHRcdFx0XHRwYXlsb2FkOiBpbmZvLFxuXHRcdFx0XHRcdF93cG5vbmNlOiBfd3Bub25jZVxuXHRcdFx0XHR9LFxuXHRcdFx0XHRzdWNjZXNzOiBjYWxsYmFja1xuXHRcdFx0fSlcblx0XHR9IGVsc2Uge1xuXHRcdFx0Y2FsbGJhY2soIHsgc3VjY2VzczpmYWxzZSwgbWVzc2FnZTppbmZvIH0gKVxuXHRcdH1cblx0fSlcbn1cblxuXG5jb25zdCBsb2dpbiA9ICggb3B0cywgY2FsbGJhY2sgKSA9PiB7XG5cblx0Y29uc3QgeyBhY3Rpb24sIHBheWxvYWQsIF93cG5vbmNlIH0gPSBvcHRzO1xuXG5cdHdlYmF1dGhuQXV0aGVudGljYXRlKCBwYXlsb2FkLCAoIHN1Y2Nlc3MsIGluZm8gKSA9PiB7XG5cdFx0aWYgKCBzdWNjZXNzICkge1xuXHRcdFx0Y2FsbGJhY2soIHsgc3VjY2Vzczp0cnVlLCByZXN1bHQ6IGluZm8gfSApXG5cdFx0fSBlbHNlIHtcblx0XHRcdGNhbGxiYWNrKCB7IHN1Y2Nlc3M6ZmFsc2UsIG1lc3NhZ2U6IGluZm8gfSApXG5cdFx0fVxuXG5cdH0pXG59XG5cbmNvbnN0IHNlbmRSZXF1ZXN0ID0gKCBvcHRzLCBjYWxsYmFjayApID0+IHtcblxuXHRjb25zdCB7IGFjdGlvbiwgcGF5bG9hZCwgX3dwbm9uY2UgfSA9IG9wdHM7XG5cblx0JC5hamF4KHtcblx0XHR1cmw6IHdwLmFqYXguc2V0dGluZ3MudXJsLFxuXHRcdG1ldGhvZDogJ3Bvc3QnLFxuXHRcdGRhdGE6IHtcblx0XHRcdGFjdGlvbjogYWN0aW9uLFxuXHRcdFx0cGF5bG9hZDogcGF5bG9hZCxcblx0XHRcdF93cG5vbmNlOiBfd3Bub25jZVxuXHRcdH0sXG5cdFx0c3VjY2VzczpjYWxsYmFja1xuXHR9KVxufVxuXG5jb25zdCBpc1dlYmF1dGhuU3VwcG9ydGVkID0gJ2NyZWRlbnRpYWxzJyBpbiBuYXZpZ2F0b3JcblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdHJlZ2lzdGVyLFxuXHRsb2dpbixcblx0c2VuZFJlcXVlc3QsXG5cdGlzV2ViYXV0aG5TdXBwb3J0ZWRcbn1cbiIsImltcG9ydCAkIGZyb20gJ2pxdWVyeSdcbmltcG9ydCB7IGxvZ2luLCBpc1dlYmF1dGhuU3VwcG9ydGVkIH0gZnJvbSAnZGF2aWRlYXJsLXdlYmF1dGhuJ1xuXG4vKipcbiAqXHRTb21lIFBhc3N3b3JkIE1hbmFnZXJzIChsaWtlIG5leHRjbG91ZCBwYXNzd29yZHMpIHNlZW0gdG8gYWJvcnQgdGhlXG4gKlx0a2V5IGJyb3dzZXIgZGlhbG9nLlxuICpcdFdlIGhhdmUgdG8gcmV0cnkgYSBjb3VwbGUgb2YgdGltZXMgdG9cbiAqL1xuY29uc3QgYXV0aCA9ICgpID0+IHtcblx0JCgnLndlYmF1dGhuLXJldHJ5JykucmVtb3ZlQ2xhc3MoJ3Zpc2libGUnKVxuXHRsb2dpbiggd2luZG93LndlYmF1dGhuTDEwbiwgcmVzcG9uc2UgPT4ge1xuXHRcdGlmICggcmVzcG9uc2Uuc3VjY2VzcyApIHtcblx0XHRcdCQoJyN3ZWJhdXRobl9yZXNwb25zZScpLnZhbCggcmVzcG9uc2UucmVzdWx0IClcblx0XHRcdCQoICcjbG9naW5mb3JtJyApLnN1Ym1pdCgpXG5cdFx0fSBlbHNlIHtcblx0XHRcdC8vIHNob3cgcmV0cnktYnV0dG9uXG5cdFx0XHQkKCcud2ViYXV0aG4tcmV0cnknKS5hZGRDbGFzcygndmlzaWJsZScpXG5cdFx0fVxuXHR9ICk7XG59XG5cbmlmICggISB3aW5kb3cud2ViYXV0aG5MMTBuICkge1xuXHRjb25zb2xlLmVycm9yKCAnd2ViYXV0aEwxMG4gaXMgbm90IGRlZmluZWQnICk7XG59O1xuXG5pZiAoIGlzV2ViYXV0aG5TdXBwb3J0ZWQgKSB7XG5cdCQoZG9jdW1lbnQpXG5cdFx0LnJlYWR5KCAoKSA9PiBhdXRoKCkgKVxuXHRcdC5vbignY2xpY2snLCcud2ViYXV0aG4tcmV0cnktbGluaycsICgpID0+IGF1dGgoKSApO1xufSBlbHNlIHtcblx0Ly8gc2hvdyBtZXNzYWdlXG5cdCQoJy53ZWJhdXRobi11bnN1cHBvcnRlZCcpLmFkZENsYXNzKCd2aXNpYmxlJylcbn1cbiJdfQ==
/*

License for promise-polyfill (MIT; see below):
Copyright (c) 2014 Taylor Hakes
Copyright (c) 2014 Forbes Lindesay

License for whatwg-fetch (MIT; see below):
Copyright (c) 2014-2016 GitHub, Inc.

License for url-polyfill (MIT; see below):
Copyright (c) 2017 Valentin Richard

License for webcrypto-shim (MIT; see below):
Copyright (c) 2015 Artem S Vybornov

MIT License:
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
/*

License for AppAuth-JS (Apache 2.0) :
Copyright (c) 2019 The OpenID Foundation

License for AppAuthHelper (Apache 2.0) :
Copyright (c) 2019 ForgeRock, Inc.

*/
"use strict";(function(a){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=a();else if("function"==typeof define&&define.amd)define([],a);else{var b;b="undefined"==typeof window?"undefined"==typeof global?"undefined"==typeof self?this:self:global:window,b.AppAuthHelper=a()}})(function(){return function(){function b(d,e,g){function a(j,i){if(!e[j]){if(!d[j]){var f="function"==typeof require&&require;if(!i&&f)return f(j,!0);if(h)return h(j,!0);var c=new Error("Cannot find module '"+j+"'");throw c.code="MODULE_NOT_FOUND",c}var k=e[j]={exports:{}};d[j][0].call(k.exports,function(b){var c=d[j][1][b];return a(c||b)},k,k.exports,b,d,e,g)}return e[j].exports}for(var h="function"==typeof require&&require,c=0;c<g.length;c++)a(g[c]);return a}return b}()({1:[function(a,b){(function(){"use strict";b.exports=function(a,b){return this.resourceServers=a,this.transmissionPort=b,this.failedRequestQueue=this.failedRequestQueue||{},this},b.exports.prototype={renewTokens:function renewTokens(a){this.transmissionPort.postMessage({message:"renewTokens",resourceServer:a})},getResourceServerFromUrl:function getResourceServerFromUrl(a){return this.resourceServers.filter(b=>0===a.indexOf(b))[0]},waitForRenewedToken:function waitForRenewedToken(a){return new Promise((b,c)=>{this.failedRequestQueue[a]||(this.failedRequestQueue[a]=[]),this.failedRequestQueue[a].push([b,c])})},retryFailedRequests:function retryFailedRequests(a){if(this.failedRequestQueue&&this.failedRequestQueue[a])for(var b=this.failedRequestQueue[a].shift();b;)b[0](),b=this.failedRequestQueue[a].shift()},sendRequestMessage:function sendRequestMessage(a){return new Promise((b,c)=>{var d=new MessageChannel;this.transmissionPort.postMessage({message:"makeRSRequest",request:a},[d.port2]),d.port1.onmessage=a=>{a.data.response?this.deserializeResponse(a.data.response).then(b):c(a.data.error)}})},interceptRequest:function interceptRequest(a,b){return new Promise((c,d)=>this.serializeRequest(a).then(a=>this.sendRequestMessage(a).then(c,e=>{"invalid_token"===e?(this.waitForRenewedToken(b).then(()=>this.sendRequestMessage(a)).then(c,d),this.renewTokens(b)):d(e)})))},serializeRequest:function serializeRequest(){},deserializeResponse:function deserializeResponse(){}}})()},{}],2:[function(a,b){(function(){"use strict";var c=a("./IdentityProxyCore"),d=function(){var a=this,b=XMLHttpRequest.prototype.open,d=XMLHttpRequest.prototype.setRequestHeader,e=XMLHttpRequest.prototype.getAllResponseHeaders,f=XMLHttpRequest.prototype.getResponseHeader,g=XMLHttpRequest.prototype.send;return XMLHttpRequest.prototype.open=function(a,c,d){if("undefined"!=typeof d&&!d)throw"Synchronous XHR requests not supported";var e=document.createElement("a");return e.href=c,this.url=e.href,this.method=a,b.apply(this,arguments)},XMLHttpRequest.prototype.setRequestHeader=function(a,b){return this.headers=this.headers||{},a=a.toLowerCase(),this.headers[a]=this.headers[a]?"".concat(this.headers[a],",").concat(b):b,d.call(this,a,b)},XMLHttpRequest.prototype.send=function(b){if(this.headers&&"true"===this.headers["x-appauthhelper-anonymous"])return this.customResponse=!1,void g.call(this,b);var c=a.getResourceServerFromUrl(this.url);c&&!this.headers.authorization?(this.customResponse=!0,a.interceptRequest({xhr:this,body:b},c).then(()=>{Object.defineProperty(this,"readyState",{get:function get(){return 4}}),Object.defineProperty(this,"status",{get:function get(){return a.response.init.status}}),Object.defineProperty(this,"statusText",{get:function get(){return a.response.init.statusText}}),Object.defineProperty(this,"responseText",{get:function get(){return a.response.body}}),Object.defineProperty(this,"response",{get:function get(){switch(this.responseType){case"json":try{return JSON.parse(this.responseText)}catch(a){return null}case"document":return new DOMParser().parseFromString(this.responseText,"application/xml");default:return this.responseText;}}}),Object.defineProperty(this,"responseXML",{get:function get(){return this.response}}),this.onload&&this.onload(),this.onloadend&&this.onloadend(),this.onreadystatechange&&this.onreadystatechange()})):(this.customResponse=!1,g.call(this,b))},XMLHttpRequest.prototype.getAllResponseHeaders=function(){return this.customResponse?Object.keys(a.response.init.headers).reduce((b,c)=>b.concat("".concat(c,": ").concat(a.response.init.headers[c],"\r\n")),""):e.call(this)},XMLHttpRequest.prototype.getResponseHeader=function(b){return this.customResponse?a.response.init.headers[b.toLowerCase()]||null:f.call(this,b)},c.apply(this,arguments)};d.prototype=Object.create(c.prototype),d.prototype.tokensRenewed=function(a){this.retryFailedRequests(a)},d.prototype.serializeRequest=function(a){return Promise.resolve({url:a.xhr.url,options:{method:a.xhr.method,headers:a.xhr.headers,body:a.body,credentials:a.xhr.withCredentials?"include":"omit"}})},d.prototype.deserializeResponse=function(a){return this.response=a,Promise.resolve(this.response)},b.exports=d})()},{"./IdentityProxyCore":1}],3:[function(a,b){(function(){"use strict";b.exports={init:function init(a){var b,c=document.createElement("a"),d=document.createElement("a");return sessionStorage.removeItem("currentResourceServer"),this.appAuthIframe=document.createElement("iframe"),this.rsIframe=document.createElement("iframe"),this.renewCooldownPeriod=a.renewCooldownPeriod||1,this.appAuthConfig={appLocation:document.location.href},this.tokensAvailableHandler=a.tokensAvailableHandler,this.interactionRequiredHandler=a.interactionRequiredHandler,this.appAuthConfig.oidc="undefined"==typeof a.oidc||!!a.oidc,this.pendingResourceServerRenewals=[],this.identityProxyPreference=a.identityProxyPreference||"serviceWorker",c.href=a.redirectUri?a.redirectUri:"appAuthHelperRedirect.html",this.appAuthConfig.redirectUri=c.href,this.iframeOrigin=new URL(this.appAuthConfig.redirectUri).origin,d.href=a.serviceWorkerUri?a.serviceWorkerUri:"appAuthServiceWorker.js",this.appAuthConfig.serviceWorkerUri=d.href,this.appAuthConfig.extras=a.extras||{},this.appAuthConfig.resourceServers=a.resourceServers||{},this.appAuthConfig.clientId=a.clientId,this.appAuthConfig.scopes=(this.appAuthConfig.oidc?["openid"]:[]).concat(Object.keys(this.appAuthConfig.resourceServers).reduce(function(a,b){return a.concat(this.appAuthConfig.resourceServers[b])}.bind(this),[])).join(" "),this.appAuthConfig.endpoints={authorization_endpoint:a.authorizationEndpoint,token_endpoint:a.tokenEndpoint,revocation_endpoint:a.revocationEndpoint,end_session_endpoint:a.endSessionEndpoint},window.addEventListener("message",function(a){if(a.origin===this.iframeOrigin)switch(a.data.message){case"appAuth-tokensAvailable":var b=sessionStorage.getItem("originalWindowHash-"+this.appAuthConfig.clientId);null!==b&&(window.location.hash=b,sessionStorage.removeItem("originalWindowHash-"+this.appAuthConfig.clientId)),a.data.resourceServer?(sessionStorage.removeItem("currentResourceServer"),this.renewTokenTimestamp=!1,this.pendingResourceServerRenewals.length&&this.pendingResourceServerRenewals.shift()(),this.identityProxy.tokensRenewed(a.data.resourceServer)):this.registerIdentityProxy().then(function(){return this.tokensAvailableHandler(a.data.idTokenClaims)}.bind(this));break;case"appAuth-interactionRequired":this.interactionRequiredHandler?this.interactionRequiredHandler(a.data.authorizationUrl,a.data.error):(window.location.hash.replace("#","").length&&sessionStorage.setItem("originalWindowHash-"+this.appAuthConfig.clientId,window.location.hash),window.location.href=a.data.authorizationUrl);break;case"appAuth-logoutComplete":this.logoutComplete();}}.bind(this),!1),this.appAuthIframe.setAttribute("src",this.appAuthConfig.redirectUri),this.appAuthIframe.setAttribute("id","AppAuthIframe"),this.appAuthIframe.setAttribute("style","display:none"),this.rsIframe.setAttribute("src",this.appAuthConfig.redirectUri),this.rsIframe.setAttribute("id","rsIframe"),this.rsIframe.setAttribute("style","display:none"),this.identityProxyMessageChannel=new MessageChannel,this.identityProxyMessageChannel.port1.onmessage=this.handleIdentityProxyMessage.bind(this),b=Promise.all([new Promise(function(a){this.rsIframe.onload=function(){this.rsIframe.onload=null,a()}.bind(this)}.bind(this)),new Promise(function(a){this.appAuthIframe.onload=function(){this.appAuthIframe.onload=null;var b=new MessageChannel;b.port1.onmessage=a,this.appAuthIframe.contentWindow.postMessage({message:"appAuth-config",config:this.appAuthConfig},this.iframeOrigin,[b.port2])}.bind(this)}.bind(this))]),document.getElementsByTagName("body")[0].appendChild(this.appAuthIframe),document.getElementsByTagName("body")[0].appendChild(this.rsIframe),b},handleIdentityProxyMessage:function handleIdentityProxyMessage(a){switch(a.data.message){case"makeRSRequest":this.rsIframe.contentWindow.postMessage({request:a.data.request,message:a.data.message,config:this.appAuthConfig},this.iframeOrigin,a.ports);break;case"renewTokens":this.renewTokens(a.data.resourceServer);}},getTokens:function getTokens(){this.appAuthIframe.contentWindow.postMessage({message:"appAuth-getAvailableData",config:this.appAuthConfig},this.iframeOrigin)},logout:function logout(){return new Promise(function(a){this.logoutComplete=a,this.appAuthIframe.contentWindow.postMessage({message:"appAuth-logout",config:this.appAuthConfig},this.iframeOrigin)}.bind(this))},whenRenewTokenFrameAvailable:function whenRenewTokenFrameAvailable(a){return new Promise(function(b){var c=sessionStorage.getItem("currentResourceServer");null===c&&(sessionStorage.setItem("currentResourceServer",a),c=a),a===c?b():this.pendingResourceServerRenewals.push(b)}.bind(this))},renewTokens:function renewTokens(a){this.whenRenewTokenFrameAvailable(a).then(function(){var b=new Date().getTime();sessionStorage.setItem("currentResourceServer",a),(!this.renewTokenTimestamp||this.renewTokenTimestamp+1e3*this.renewCooldownPeriod<b)&&(this.renewTokenTimestamp=b,this.appAuthIframe.contentWindow.postMessage({message:"appAuth-getFreshAccessToken",config:this.appAuthConfig,resourceServer:a},this.iframeOrigin))}.bind(this))},registerIdentityProxy:function registerIdentityProxy(){return new Promise(function(a){"serviceWorker"===this.identityProxyPreference&&"serviceWorker"in navigator?navigator.serviceWorker.register(this.appAuthConfig.serviceWorkerUri).then(function(b){this.identityProxy={tokensRenewed:function tokensRenewed(a){navigator.serviceWorker.controller.postMessage({message:"tokensRenewed",resourceServer:a})}};var c=function(){this.identityProxyMessageChannel.port1.onmessage=function(b){a(),this.handleIdentityProxyMessage.call(this,b)}.bind(this),b.active.postMessage({message:"configuration",resourceServers:Object.keys(this.appAuthConfig.resourceServers)},[this.identityProxyMessageChannel.port2])}.bind(this);navigator.serviceWorker.ready.then(c)}.bind(this)).catch(function(){this.registerXHRProxy(),a()}.bind(this)):(this.registerXHRProxy(),a())}.bind(this))},registerXHRProxy:function registerXHRProxy(){if("undefined"!=typeof IdentityProxyXHR)this.identityProxy=new IdentityProxyXHR(Object.keys(this.appAuthConfig.resourceServers),this.identityProxyMessageChannel.port2);else throw"Browser incompatible with this build of AppAuthHelper. Use the legacy 'compatible' build instead."}}})()},{}],4:[function(a,b){window.Promise=window.Promise||("function"==typeof a("promise-polyfill")?a("promise-polyfill"):a("promise-polyfill").default),a("url-polyfill"),window.IdentityProxyXHR=a("./IdentityProxyXHR"),b.exports=a("./appAuthHelper")},{"./IdentityProxyXHR":2,"./appAuthHelper":3,"promise-polyfill":6,"url-polyfill":8}],5:[function(a,b){function c(){throw new Error("setTimeout has not been defined")}function d(){throw new Error("clearTimeout has not been defined")}function e(a){if(l===setTimeout)return setTimeout(a,0);if((l===c||!l)&&setTimeout)return l=setTimeout,setTimeout(a,0);try{return l(a,0)}catch(b){try{return l.call(null,a,0)}catch(b){return l.call(this,a,0)}}}function f(a){if(m===clearTimeout)return clearTimeout(a);if((m===d||!m)&&clearTimeout)return m=clearTimeout,clearTimeout(a);try{return m(a)}catch(b){try{return m.call(null,a)}catch(b){return m.call(this,a)}}}function g(){q&&o&&(q=!1,o.length?p=o.concat(p):r=-1,p.length&&h())}function h(){if(!q){var a=e(g);q=!0;for(var b=p.length;b;){for(o=p,p=[];++r<b;)o&&o[r].run();r=-1,b=p.length}o=null,q=!1,f(a)}}function j(a,b){this.fun=a,this.array=b}function k(){}var l,m,n=b.exports={};(function(){try{l="function"==typeof setTimeout?setTimeout:c}catch(a){l=c}try{m="function"==typeof clearTimeout?clearTimeout:d}catch(a){m=d}})();var o,p=[],q=!1,r=-1;n.nextTick=function(a){var b=Array(arguments.length-1);if(1<arguments.length)for(var c=1;c<arguments.length;c++)b[c-1]=arguments[c];p.push(new j(a,b)),1!==p.length||q||e(h)},j.prototype.run=function(){this.fun.apply(null,this.array)},n.title="browser",n.browser=!0,n.env={},n.argv=[],n.version="",n.versions={},n.on=k,n.addListener=k,n.once=k,n.off=k,n.removeListener=k,n.removeAllListeners=k,n.emit=k,n.prependListener=k,n.prependOnceListener=k,n.listeners=function(){return[]},n.binding=function(){throw new Error("process.binding is not supported")},n.cwd=function(){return"/"},n.chdir=function(){throw new Error("process.chdir is not supported")},n.umask=function(){return 0}},{}],6:[function(a,b){(function(a){'use strict';function c(a){return!!(a&&"undefined"!=typeof a.length)}function d(){}function e(a,b){return function(){a.apply(b,arguments)}}function f(a){if(!(this instanceof f))throw new TypeError("Promises must be constructed via new");if("function"!=typeof a)throw new TypeError("not a function");this._state=0,this._handled=!1,this._value=void 0,this._deferreds=[],l(a,this)}function g(a,b){for(;3===a._state;)a=a._value;return 0===a._state?void a._deferreds.push(b):void(a._handled=!0,f._immediateFn(function(){var c=1===a._state?b.onFulfilled:b.onRejected;if(null===c)return void(1===a._state?h:i)(b.promise,a._value);var d;try{d=c(a._value)}catch(a){return void i(b.promise,a)}h(b.promise,d)}))}function h(a,b){try{if(b===a)throw new TypeError("A promise cannot be resolved with itself.");if(b&&("object"==typeof b||"function"==typeof b)){var c=b.then;if(b instanceof f)return a._state=3,a._value=b,void j(a);if("function"==typeof c)return void l(e(c,b),a)}a._state=1,a._value=b,j(a)}catch(b){i(a,b)}}function i(a,b){a._state=2,a._value=b,j(a)}function j(a){2===a._state&&0===a._deferreds.length&&f._immediateFn(function(){a._handled||f._unhandledRejectionFn(a._value)});for(var b=0,c=a._deferreds.length;b<c;b++)g(a,a._deferreds[b]);a._deferreds=null}function k(a,b,c){this.onFulfilled="function"==typeof a?a:null,this.onRejected="function"==typeof b?b:null,this.promise=c}function l(a,b){var c=!1;try{a(function(a){c||(c=!0,h(b,a))},function(a){c||(c=!0,i(b,a))})}catch(a){if(c)return;c=!0,i(b,a)}}var m=setTimeout;f.prototype["catch"]=function(a){return this.then(null,a)},f.prototype.then=function(a,b){var c=new this.constructor(d);return g(this,new k(a,b,c)),c},f.prototype["finally"]=function(a){var b=this.constructor;return this.then(function(c){return b.resolve(a()).then(function(){return c})},function(c){return b.resolve(a()).then(function(){return b.reject(c)})})},f.all=function(a){return new f(function(b,d){function e(a,c){try{if(c&&("object"==typeof c||"function"==typeof c)){var h=c.then;if("function"==typeof h)return void h.call(c,function(b){e(a,b)},d)}f[a]=c,0==--g&&b(f)}catch(a){d(a)}}if(!c(a))return d(new TypeError("Promise.all accepts an array"));var f=Array.prototype.slice.call(a);if(0===f.length)return b([]);for(var g=f.length,h=0;h<f.length;h++)e(h,f[h])})},f.resolve=function(a){return a&&"object"==typeof a&&a.constructor===f?a:new f(function(b){b(a)})},f.reject=function(a){return new f(function(b,c){c(a)})},f.race=function(a){return new f(function(b,d){if(!c(a))return d(new TypeError("Promise.race accepts an array"));for(var e=0,g=a.length;e<g;e++)f.resolve(a[e]).then(b,d)})},f._immediateFn="function"==typeof a&&function(b){a(b)}||function(a){m(a,0)},f._unhandledRejectionFn=function(a){"undefined"!=typeof console&&console&&console.warn("Possible Unhandled Promise Rejection:",a)},b.exports=f}).call(this,a("timers").setImmediate)},{timers:7}],7:[function(a,b,c){(function(b,d){function e(a,b){this._id=a,this._clearFn=b}var f=a("process/browser.js").nextTick,g=Function.prototype.apply,h=Array.prototype.slice,i={},j=0;c.setTimeout=function(){return new e(g.call(setTimeout,window,arguments),clearTimeout)},c.setInterval=function(){return new e(g.call(setInterval,window,arguments),clearInterval)},c.clearTimeout=c.clearInterval=function(a){a.close()},e.prototype.unref=e.prototype.ref=function(){},e.prototype.close=function(){this._clearFn.call(window,this._id)},c.enroll=function(a,b){clearTimeout(a._idleTimeoutId),a._idleTimeout=b},c.unenroll=function(a){clearTimeout(a._idleTimeoutId),a._idleTimeout=-1},c._unrefActive=c.active=function(a){clearTimeout(a._idleTimeoutId);var b=a._idleTimeout;0<=b&&(a._idleTimeoutId=setTimeout(function(){a._onTimeout&&a._onTimeout()},b))},c.setImmediate="function"==typeof b?b:function(a){var b=j++,d=!(2>arguments.length)&&h.call(arguments,1);return i[b]=!0,f(function(){i[b]&&(d?a.apply(null,d):a.call(null),c.clearImmediate(b))}),b},c.clearImmediate="function"==typeof d?d:function(a){delete i[a]}}).call(this,a("timers").setImmediate,a("timers").clearImmediate)},{"process/browser.js":5,timers:7}],8:[function(){(function(a){(function(a){var b=function checkIfIteratorIsSupported(){try{return!!Symbol.iterator}catch(a){return!1}}(),c=function(a){var c={next:function next(){var b=a.shift();return{done:void 0===b,value:b}}};return b&&(c[Symbol.iterator]=function(){return c}),c},d=function(a){return encodeURIComponent(a).replace(/%20/g,"+")},e=function(a){return decodeURIComponent((a+"").replace(/\+/g," "))};(function checkIfURLSearchParamsSupported(){try{var b=a.URLSearchParams;return"a=1"===new b("?a=1").toString()&&"function"==typeof b.prototype.set}catch(a){return!1}})()||function polyfillURLSearchParams(){var e=function(a){Object.defineProperty(this,"_entries",{writable:!0,value:{}});var b=typeof a;if("undefined"==b);else if("string"===b)""!=a&&this._fromString(a);else if(a instanceof e){var c=this;a.forEach(function(a,b){c.append(b,a)})}else if(!(null!==a&&"object"===b))throw new TypeError("Unsupported input's type for URLSearchParams");else if("[object Array]"===Object.prototype.toString.call(a)){for(var d,f=0;f<a.length;f++)if(d=a[f],"[object Array]"===Object.prototype.toString.call(d)||2!==d.length)this.append(d[0],d[1]);else throw new TypeError("Expected [string, any] as entry at index "+f+" of URLSearchParams's input");}else for(var g in a)a.hasOwnProperty(g)&&this.append(g,a[g])},f=e.prototype;f.append=function(a,b){a in this._entries?this._entries[a].push(b+""):this._entries[a]=[b+""]},f.delete=function(a){delete this._entries[a]},f.get=function(a){return a in this._entries?this._entries[a][0]:null},f.getAll=function(a){return a in this._entries?this._entries[a].slice(0):[]},f.has=function(a){return a in this._entries},f.set=function(a,b){this._entries[a]=[b+""]},f.forEach=function(a,b){var c;for(var d in this._entries)if(this._entries.hasOwnProperty(d)){c=this._entries[d];for(var e=0;e<c.length;e++)a.call(b,c[e],d,this)}},f.keys=function(){var a=[];return this.forEach(function(b,c){a.push(c)}),c(a)},f.values=function(){var a=[];return this.forEach(function(b){a.push(b)}),c(a)},f.entries=function(){var a=[];return this.forEach(function(b,c){a.push([c,b])}),c(a)},b&&(f[Symbol.iterator]=f.entries),f.toString=function(){var a=[];return this.forEach(function(b,c){a.push(d(c)+"="+d(b))}),a.join("&")},a.URLSearchParams=e}();var f=a.URLSearchParams.prototype;"function"!=typeof f.sort&&(f.sort=function(){var a=this,b=[];this.forEach(function(c,d){b.push([d,c]),a._entries||a.delete(d)}),b.sort(function(c,a){return c[0]<a[0]?-1:c[0]>a[0]?1:0}),a._entries&&(a._entries={});for(var c=0;c<b.length;c++)this.append(b[c][0],b[c][1])}),"function"!=typeof f._fromString&&Object.defineProperty(f,"_fromString",{enumerable:!1,configurable:!1,writable:!1,value:function value(a){if(this._entries)this._entries={};else{var b=[];this.forEach(function(a,c){b.push(c)});for(var c=0;c<b.length;c++)this.delete(b[c])}a=a.replace(/^\?/,"");for(var d,f=a.split("&"),c=0;c<f.length;c++)d=f[c].split("="),this.append(e(d[0]),1<d.length?e(d[1]):"")}})})("undefined"==typeof a?"undefined"==typeof window?"undefined"==typeof self?this:self:window:a),function(a){if(function checkIfURLIsSupported(){try{var b=new a.URL("b","http://a");return b.pathname="c d","http://a/c%20d"===b.href&&b.searchParams}catch(a){return!1}}()||function polyfillURL(){var b=a.URL,c=function(b,c){"string"!=typeof b&&(b+="");var d,e=document;if(c&&(void 0===a.location||c!==a.location.href)){e=document.implementation.createHTMLDocument(""),d=e.createElement("base"),d.href=c,e.head.appendChild(d);try{if(0!==d.href.indexOf(c))throw new Error(d.href)}catch(a){throw new Error("URL unable to set base "+c+" due to "+a)}}var f=e.createElement("a");f.href=b,d&&(e.body.appendChild(f),f.href=f.href);var g=e.createElement("input");if(g.type="url",g.value=b,":"===f.protocol||!/:/.test(f.href)||!g.checkValidity()&&!c)throw new TypeError("Invalid URL");Object.defineProperty(this,"_anchorElement",{value:f});var h=new a.URLSearchParams(this.search),i=!0,j=!0,k=this;["append","delete","set"].forEach(function(a){var b=h[a];h[a]=function(){b.apply(h,arguments),i&&(j=!1,k.search=h.toString(),j=!0)}}),Object.defineProperty(this,"searchParams",{value:h,enumerable:!0});var l;Object.defineProperty(this,"_updateSearchParams",{enumerable:!1,configurable:!1,writable:!1,value:function value(){this.search!==l&&(l=this.search,j&&(i=!1,this.searchParams._fromString(this.search),i=!0))}})},d=c.prototype,e=function(a){Object.defineProperty(d,a,{get:function get(){return this._anchorElement[a]},set:function set(b){this._anchorElement[a]=b},enumerable:!0})};["hash","host","hostname","port","protocol"].forEach(function(a){e(a)}),Object.defineProperty(d,"search",{get:function get(){return this._anchorElement.search},set:function set(a){this._anchorElement.search=a,this._updateSearchParams()},enumerable:!0}),Object.defineProperties(d,{toString:{get:function get(){var a=this;return function(){return a.href}}},href:{get:function get(){return this._anchorElement.href.replace(/\?$/,"")},set:function set(a){this._anchorElement.href=a,this._updateSearchParams()},enumerable:!0},pathname:{get:function get(){return this._anchorElement.pathname.replace(/(^\/?)/,"/")},set:function set(a){this._anchorElement.pathname=a},enumerable:!0},origin:{get:function get(){var a={"http:":80,"https:":443,"ftp:":21}[this._anchorElement.protocol],b=this._anchorElement.port!=a&&""!==this._anchorElement.port;return this._anchorElement.protocol+"//"+this._anchorElement.hostname+(b?":"+this._anchorElement.port:"")},enumerable:!0},password:{get:function get(){return""},set:function set(){},enumerable:!0},username:{get:function get(){return""},set:function set(){},enumerable:!0}}),c.createObjectURL=function(){return b.createObjectURL.apply(b,arguments)},c.revokeObjectURL=function(){return b.revokeObjectURL.apply(b,arguments)},a.URL=c}(),void 0!==a.location&&!("origin"in a.location)){var b=function(){return a.location.protocol+"//"+a.location.hostname+(a.location.port?":"+a.location.port:"")};try{Object.defineProperty(a.location,"origin",{get:b,enumerable:!0})}catch(c){setInterval(function(){a.location.origin=b()},100)}}}("undefined"==typeof a?"undefined"==typeof window?"undefined"==typeof self?this:self:window:a)}).call(this,"undefined"==typeof global?"undefined"==typeof self?"undefined"==typeof window?{}:window:self:global)},{}]},{},[4])(4)});

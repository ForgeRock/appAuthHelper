/*

License for AppAuth-JS (Apache 2.0) :
Copyright (c) 2019 The OpenID Foundation

License for AppAuthHelper (Apache 2.0) :
Copyright (c) 2019 ForgeRock, Inc.

*/
"use strict";(function(){function b(d,e,g){function a(j,i){if(!e[j]){if(!d[j]){var f="function"==typeof require&&require;if(!i&&f)return f(j,!0);if(h)return h(j,!0);var c=new Error("Cannot find module '"+j+"'");throw c.code="MODULE_NOT_FOUND",c}var k=e[j]={exports:{}};d[j][0].call(k.exports,function(b){var c=d[j][1][b];return a(c||b)},k,k.exports,b,d,e,g)}return e[j].exports}for(var h="function"==typeof require&&require,c=0;c<g.length;c++)a(g[c]);return a}return b})()({1:[function(a,b){(function(){"use strict";var a={};b.exports=function(a,b,c){return this.addProxyCore(a,b,c),this},b.exports.prototype={setProxyCoreByUrl:function(b){let c=Object.keys(a).filter(c=>a[c].resourceServers.filter(a=>0<=b.indexOf(a)))[0];c?(this.resourceServers=a[c].resourceServers,this.transmissionPort=a[c].transmissionPort,this.failedRequestQueue=a[c].failedRequestQueue):(this.resourceServers=[],this.transmissionPort={},this.failedRequestQueue={})},addProxyCore:function(b,c,d){a[d]={resourceServers:b,transmissionPort:c,failedRequestQueue:this.failedRequestQueue||{}}},removeProxyCore:function(b){delete a[b]},renewTokens:function(a){this.setProxyCoreByUrl(a),this.transmissionPort.postMessage({message:"renewTokens",resourceServer:a})},getResourceServerFromUrl:function(a){return this.resourceServers.filter(b=>0===a.indexOf(b))[0]},waitForRenewedToken:function(a){return new Promise((b,c)=>{this.failedRequestQueue[a]||(this.failedRequestQueue[a]=[]),this.failedRequestQueue[a].push([b,c])})},retryFailedRequests:function(a){if(this.failedRequestQueue&&this.failedRequestQueue[a])for(var b=this.failedRequestQueue[a].shift();b;)b[0](),b=this.failedRequestQueue[a].shift()},sendRequestMessage:function(a){return new Promise((b,c)=>{var d=new MessageChannel;this.transmissionPort.postMessage({message:"makeRSRequest",request:a},[d.port2]),d.port1.onmessage=a=>{a.data.response?this.deserializeResponse(a.data.response).then(b):c(a.data.error)}})},fixupBlobContentType:function(a){var b=a.type.match(/multipart\/form-data; boundary=(----webkitformboundary.*)/);return b?new Promise(c=>{a.arrayBuffer().then(d=>{var e=new TextDecoder().decode(d),f=e.match(/--(-+WebKitFormBoundary.*)/);2<=f.length?c(new Blob([e.replace(new RegExp(f[1],"g"),b[1])],{type:a.type})):c(a)})}):Promise.resolve(a)},interceptRequest:function(a,b){return new Promise((c,d)=>this.serializeRequest(a).then(a=>this.sendRequestMessage(a).then(c,e=>{"invalid_token"===e?(this.waitForRenewedToken(b).then(()=>this.sendRequestMessage(a)).then(c,d),this.renewTokens(b)):d(e)})))},serializeRequest:function(){},deserializeResponse:function(){}}})()},{}],2:[function(a,b){(function(){"use strict";var c=a("./IdentityProxyCore"),d=function(){return c.apply(this,arguments)};d.prototype=Object.create(c.prototype),d.prototype.serializeHeaders=function(a){let b={};for(let c of a.keys())b[c]=a.get(c);return b},d.prototype.serializeRequest=function(a){return new Promise(b=>{a.clone().blob().then(a=>this.fixupBlobContentType(a)).then(c=>b({url:a.url,options:{method:a.method,headers:this.serializeHeaders(a.headers),body:-1===["GET","HEAD"].indexOf(a.method.toUpperCase())&&c&&c.size?c:void 0,mode:a.mode,credentials:a.credentials,cache:a.cache,redirect:a.redirect,referrer:a.referrer,integrity:a.integrity}}))})},d.prototype.deserializeResponse=function(a){return Promise.resolve(new Response(a.body,a.init))},b.exports=d})()},{"./IdentityProxyCore":1}],3:[function(a){(function(){"use strict";var b=a("./IdentityProxyServiceWorker");self.addEventListener("install",a=>{a.waitUntil(self.skipWaiting())}),self.addEventListener("activate",a=>{a.waitUntil(self.clients.claim())}),self.addEventListener("message",a=>{"configuration"===a.data.message?(self.identityProxy=new b(a.data.resourceServers,a.ports[0]),a.waitUntil(self.clients.claim().then(()=>a.ports[0].postMessage({message:"configured"})))):"tokensRenewed"===a.data.message&&self.identityProxy.retryFailedRequests(a.data.resourceServer)}),self.addEventListener("fetch",a=>{if("true"!==a.request.headers.get("x-appauthhelper-anonymous")&&self.identityProxy){var b=self.identityProxy.getResourceServerFromUrl(a.request.url);b&&!a.request.headers.get("authorization")&&a.respondWith(self.identityProxy.interceptRequest(a.request,b))}})})()},{"./IdentityProxyServiceWorker":2}]},{},[3]);

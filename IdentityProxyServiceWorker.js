(function () {
    "use strict";

    var IdentityProxyCore = require("./IdentityProxyCore"),
        IdentityProxyServiceWorker = function () {
            return IdentityProxyCore.apply(this, arguments);
        };

    IdentityProxyServiceWorker.prototype = Object.create(IdentityProxyCore.prototype);

    IdentityProxyServiceWorker.prototype.serializeHeaders = function (headers) {
        let headersObj = {};
        for (let key of headers.keys()) {
            headersObj[key] = headers.get(key);
        }
        return headersObj;
    };

    IdentityProxyServiceWorker.prototype.serializeRequest = function (request) {
        return new Promise((resolve) => {
            request.clone().blob()
                .then((bodyBlob) => this.fixupBlobContentType(bodyBlob))
                .then((bodyBlob) =>
                    resolve({
                        url: request.url,
                        options: {
                            method: request.method,
                            headers: this.serializeHeaders(request.headers),
                            body: ["GET","HEAD"].indexOf(request.method.toUpperCase()) === -1 && bodyBlob && bodyBlob.size ? bodyBlob : undefined,
                            mode: request.mode,
                            credentials: request.credentials,
                            cache: request.cache,
                            redirect: request.redirect,
                            referrer: request.referrer,
                            integrity: request.integrity
                        }
                    })
                );
        });
    };

    IdentityProxyServiceWorker.prototype.deserializeResponse = function (serializedResponse) {
        return Promise.resolve(new Response(serializedResponse.body, serializedResponse.init));
    };

    module.exports = IdentityProxyServiceWorker;

}());

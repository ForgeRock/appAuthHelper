(function () {
    "use strict";

    module.exports = function IdentityProxyCore(resourceServers, transmissionPort) {
        this.resourceServers = resourceServers;
        this.transmissionPort = transmissionPort;
        this.failedRequestQueue = this.failedRequestQueue || {};
        return this;
    };

    module.exports.prototype = {
        renewTokens: function (resourceServer) {
            this.transmissionPort.postMessage({
                "message": "renewTokens",
                "resourceServer": resourceServer
            });
        },
        getResourceServerFromUrl: function (url) {
            return this.resourceServers.filter((rs) => url.indexOf(rs) === 0)[0];
        },
        waitForRenewedToken: function (resourceServer) {
            return new Promise((resolve, reject) => {
                if (!this.failedRequestQueue[resourceServer]) {
                    this.failedRequestQueue[resourceServer] = [];
                }
                this.failedRequestQueue[resourceServer].push([resolve, reject]);
            });
        },
        retryFailedRequests: function (resourceServer) {
            if (this.failedRequestQueue && this.failedRequestQueue[resourceServer]) {
                var p = this.failedRequestQueue[resourceServer].shift();
                while (p) {
                    p[0]();
                    p = this.failedRequestQueue[resourceServer].shift();
                }
            }
        },
        sendRequestMessage: function (serializedRequest) {
            return new Promise((resolve, reject) => {
                var mc = new MessageChannel();
                this.transmissionPort.postMessage({
                    "message": "makeRSRequest",
                    "request": serializedRequest
                }, [mc.port2]);
                mc.port1.onmessage = (event) => {
                    if (event.data.response) {
                        this.deserializeResponse(event.data.response).then(resolve);
                    } else {
                        reject(event.data.error);
                    }
                };
            });
        },
        fixupBlobContentType: function (originalBlob) {
            // work around for a bug in webkit which does not set the case of the boundary in the request content properly
            var typeParts = originalBlob.type.match(/multipart\/form-data; boundary=(----webkitformboundary.*)/);
            if (!typeParts) {
                return Promise.resolve(originalBlob);
            } else {
                return new Promise((resolve) => {
                    originalBlob.arrayBuffer()
                    .then((buf) => {
                        var decodedContent = (new TextDecoder()).decode(buf),
                            contentParts = decodedContent.match(/--(-+WebKitFormBoundary.*)/);
                        if (contentParts.length >= 2) {
                            // replace the mixed-case boundary references with the lowercase one set in the blob type
                            resolve(new Blob([decodedContent.replace(new RegExp(contentParts[1], "g"), typeParts[1])], {type: originalBlob.type}));
                        } else {
                            resolve(originalBlob);
                        }
                    });
                });
            }
        },
        interceptRequest: function (request, resourceServer) {
            return new Promise((resolve, reject) =>
                this.serializeRequest(request).then((serializedRequest) =>
                    this.sendRequestMessage(serializedRequest).then(resolve, (error) => {
                        if (error === "invalid_token") {
                            this.waitForRenewedToken(resourceServer)
                                .then(() => this.sendRequestMessage(serializedRequest))
                                .then(resolve, reject);

                            this.renewTokens(resourceServer);
                        } else {
                            reject(error);
                        }
                    })
                )
            );
        },
        serializeRequest: function () {/* implementation needed*/},
        deserializeResponse: function () {/* implementation needed*/}
    };
}());

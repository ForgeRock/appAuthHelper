self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", () => {
    self.clients.claim();
});

self.addEventListener("message", (event) => {
    if (event.data.message === "configuration") {
        self.appAuthConfig = event.data.config;
        self.failedRequestQueue = self.failedRequestQueue || {};
        self.messageChannel = event.ports[0];
        self.messageChannel.postMessage({
            "message": "configured"
        });
    } else if (event.data.message === "tokensRenewed") {
        self.retryFailedRequests(event.data.resourceServer);
    }
});

self.waitForRenewedToken = function (resourceServer) {
    return new Promise((resolve, reject) => {
        if (!self.failedRequestQueue[resourceServer]) {
            self.failedRequestQueue[resourceServer] = [];
        }
        self.failedRequestQueue[resourceServer].push([resolve, reject]);
    });
};

self.retryFailedRequests = function (resourceServer) {
    if (self.failedRequestQueue && self.failedRequestQueue[resourceServer]) {
        var p = self.failedRequestQueue[resourceServer].shift();
        while (p) {
            p[0]();
            p = self.failedRequestQueue[resourceServer].shift();
        }
    }
};

self.addAccessTokenToRequest = function (request, resourceServer) {
    return new Promise((resolve, reject) => {
        var dbReq = indexedDB.open("appAuth",1);
        dbReq.onupgradeneeded = () => {
            dbReq.result.createObjectStore(this.appAuthConfig.clientId);
        };
        dbReq.onerror = reject;
        dbReq.onsuccess = () => {
            var objectStoreRequest = dbReq.result.transaction([self.appAuthConfig.clientId], "readonly")
                .objectStore(self.appAuthConfig.clientId).get("tokens");

            objectStoreRequest.onerror = reject;

            objectStoreRequest.onsuccess = () => {
                var tokens = objectStoreRequest.result,
                    rsHeaders =  new Headers(request.headers);

                dbReq.result.close();

                if (!tokens[resourceServer]) {
                    self.waitForRenewedToken(resourceServer).then(() => {
                        self.addAccessTokenToRequest(request, resourceServer).then(resolve, reject);
                    }, reject);
                    self.messageChannel.postMessage({
                        "message":"renewTokens",
                        "resourceServer": resourceServer
                    });
                } else {
                    rsHeaders.set("Authorization", `Bearer ${tokens[resourceServer]}`);

                    resolve(new Request(request.url, {
                        method: request.method,
                        headers: rsHeaders,
                        body: request.body,
                        mode: request.mode,
                        credentials: request.credentials,
                        cache: request.cache,
                        redirect: request.redirect,
                        referrer: request.referrer,
                        integrity: request.integrity
                    }));
                }
            };
        };
    });
};

self.addEventListener("fetch", (event) => {
    if (self.appAuthConfig &&
        typeof self.appAuthConfig.resourceServers === "object" &&
        Object.keys(self.appAuthConfig.resourceServers).length) {

        var resourceServer = Object.keys(self.appAuthConfig.resourceServers)
            .filter((rs) => event.request.url.indexOf(rs) === 0)[0];

        if (resourceServer) {
            event.respondWith(new Promise((resolve, reject) => {
                self.addAccessTokenToRequest(event.request, resourceServer).then((rsRequest) => {
                    fetch(rsRequest).then((resp) => {
                        if (!resp.ok) {
                            // Watch for errors as described by https://tools.ietf.org/html/rfc6750#section-3
                            var auth_header = resp.headers.get("www-authenticate");
                            if (auth_header && auth_header.match(/^Bearer /)) {
                                var auth_details = auth_header
                                    .replace(/^Bearer /, "")
                                    .match(/[^,=]+=".*?"/g)
                                    .reduce(function (result, detail) {
                                        var pair = detail.split("=");
                                        result[pair[0]] = pair[1].replace(/"(.*)"/, "$1");
                                        return result;
                                    }, {});

                                if (auth_details["error"] === "invalid_token") {
                                    /*
                                    From https://tools.ietf.org/html/rfc6750#section-3.1:
                                    invalid_token
                                         The access token provided is expired, revoked, malformed, or
                                         invalid for other reasons.  The resource SHOULD respond with
                                         the HTTP 401 (Unauthorized) status code.  The client MAY
                                         request a new access token and retry the protected resource
                                         request.

                                    We are going to follow the RFC's advice here and try to request a new
                                    access token and retry the request.
                                    */
                                    self.waitForRenewedToken(resourceServer).then(() => {
                                        self.addAccessTokenToRequest(event.request, resourceServer).then((freshRSRequest) => {
                                            fetch(freshRSRequest).then(
                                                (resp) => resolve(resp),
                                                (failure) => reject(failure)
                                            );
                                        });
                                    }, reject);
                                    self.messageChannel.postMessage({
                                        "message":"renewTokens",
                                        "resourceServer": resourceServer
                                    });
                                } else {
                                    resolve(resp);
                                }
                            } else {
                                resolve(resp);
                            }
                        } else {
                            resolve(resp);
                        }
                    }, reject);
                });
            }));
        }

    }

    return;
});

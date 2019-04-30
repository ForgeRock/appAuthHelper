self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", () => {
    self.clients.claim();
});

self.addEventListener("message", (event) => {
    if (event.data.message === "configuration") {
        self.appAuthConfig = event.data.config;
        self.failedRequestQueue = [];
        self.messageChannel = event.ports[0];
        self.messageChannel.postMessage("configured");
    } else if (event.data.message === "tokensRenewed") {
        self.retryFailedRequests();
    }
});

self.waitForRenewedToken = function () {
    return new Promise((resolve, reject) => {
        self.failedRequestQueue.push([resolve, reject]);
    });
};

self.retryFailedRequests = function () {
    var p = self.failedRequestQueue.shift();
    while (p) {
        p[0]();
        p = self.failedRequestQueue.shift();
    }
};

self.addAccessTokenToRequest = function (request) {
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

                if (tokens.accessToken) {
                    rsHeaders.set("Authorization", `Bearer ${tokens.accessToken}`);
                }

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
            };
        };
    });
};

self.addEventListener("fetch", (event) => {
    if (self.appAuthConfig &&
        typeof self.appAuthConfig.resourceServers === "object" &&
        self.appAuthConfig.resourceServers.length &&
        self.appAuthConfig.resourceServers.reduce((result, rs) =>
            result || event.request.url.indexOf(rs) === 0,
        false)
    ) {
        event.respondWith(new Promise((resolve, reject) => {
            self.addAccessTokenToRequest(event.request).then((rsRequest) => {
                fetch(rsRequest).then((resp) => {
                    if (!resp.ok) {
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
                                // This request appears to have failed due to an expired token.
                                // We may be able to transparently resolve this problem by
                                // going back to the OP for a new one, in which case we can
                                // replay the request.
                                self.waitForRenewedToken().then(() => {
                                    self.addAccessTokenToRequest(event.request).then((freshRSRequest) => {
                                        fetch(freshRSRequest).then(
                                            (resp) => resolve(resp),
                                            (failure) => reject(failure)
                                        );
                                    });
                                }, reject);
                                self.messageChannel.postMessage("renewTokens");
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

    return;
});

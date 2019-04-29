
self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", () => {
    self.clients.claim();
});

self.addEventListener("message", (event) => {
    self.appAuthConfig = event.data;
    event.ports[0].postMessage(true);
});

self.addEventListener("fetch", (event) => {
    /**
     * Accepts an xhr object that has been completed (after "loadend") and checks to see
     * if it includes a response header that indicated that it failed due to an invalid token
     * @returns boolean - true if due to invalid_token, false otherwise
     */
    /*
    function checkForTokenFailure(xhr) {
        var response_headers = xhr.getAllResponseHeaders()
            .split("\n")
            .map(function (header) {
                return header.split(": ");
            })
            .reduce(function (result, pair) {
                if (pair.length === 2) {
                    result[pair[0]] = pair[1];
                }
                return result;
            }, {});

        if (response_headers["www-authenticate"] && response_headers["www-authenticate"].match(/^Bearer /)) {
            var auth_details = response_headers["www-authenticate"]
                .replace(/^Bearer /, "")
                .match(/[^,=]+=".*?"/g)
                .reduce(function (result, detail) {
                    var pair = detail.split("=");
                    result[pair[0]] = pair[1].replace(/"(.*)"/, "$1");
                    return result;
                }, {});

            if (auth_details["error"] === "invalid_token") {
                return true;
            }
        }

        return false;
    }
    */


    if (self.appAuthConfig &&
        typeof self.appAuthConfig.resourceServers === "object" &&
        self.appAuthConfig.resourceServers.length &&
        self.appAuthConfig.resourceServers.reduce((result, rs) =>
            result || event.request.url.indexOf(rs) === 0,
        false)
    ) {
        event.respondWith(new Promise((resolve, reject) => {
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
                        rsHeaders =  new Headers(event.request.headers),
                        rsRequest;

                    rsHeaders.set("Authorization", `Bearer ${tokens.accessToken}`);
                    rsRequest = new Request(event.request.url, {
                        method: event.request.method,
                        headers: rsHeaders,
                        body: event.request.body,
                        mode: event.request.mode,
                        credentials: event.request.credentials,
                        cache: event.request.cache,
                        redirect: event.request.redirect,
                        referrer: event.request.referrer,
                        integrity: event.request.integrity
                    });
                    resolve(fetch(rsRequest));
                };
            };
        }));
    }

    return;
});

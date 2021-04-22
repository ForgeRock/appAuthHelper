(function () {
    "use strict";

    var AppAuth = require("@openid/appauth");

    module.exports = function (config) {
        this.appAuthConfig = config;

        this.client = {
            clientId: this.appAuthConfig.clientId,
            scopes: this.appAuthConfig.scopes,
            redirectUri: this.appAuthConfig.redirectUri,
            configuration: new AppAuth.AuthorizationServiceConfiguration(this.appAuthConfig.endpoints),
            notifier: new AppAuth.AuthorizationNotifier(),
            authorizationHandler: new AppAuth.RedirectRequestHandler(),
            tokenHandler: new AppAuth.BaseTokenRequestHandler(new AppAuth.FetchRequestor())
        };

        this.client.authorizationHandler.setAuthorizationNotifier(this.client.notifier);

        /**
         * This is invoked when the browser has returned from the OP with either a code or an error.
         */
        this.client.notifier.setAuthorizationListener((function (request, response, error) {
            if (response) {
                this.client.request = request;
                this.client.response = response;
                this.client.code = response.code;
            }
            if (error) {
                this.client.error = error;
            }
        }).bind(this));

        return this;
    };

    module.exports.prototype = {
        /**
            Do whatever it takes to get the latest user claims. If there is a pending authz request,
            complete it. If not, check to see if there are stored tokens available. If there is no way
            to return claims, then reject the promise.
        */
        getAvailableData: function () {
            return new Promise((function (resolve, reject) {
                this.client.authorizationHandler.completeAuthorizationRequestIfPossible().then((function () {
                    var request;
                    // The case when the user has successfully returned from the authorization request
                    if (this.client.code) {
                        var extras = {};
                        // PKCE support
                        if (this.client.request && this.client.request.internal) {
                            extras["code_verifier"] = this.client.request.internal["code_verifier"];
                        }
                        request = new AppAuth.TokenRequest({
                            client_id: this.client.clientId,
                            redirect_uri: this.client.redirectUri,
                            grant_type: AppAuth.GRANT_TYPE_AUTHORIZATION_CODE,
                            code: this.client.code,
                            refresh_token: undefined,
                            extras: extras
                        });
                        this.client.tokenHandler
                            .performTokenRequest(this.client.configuration, request)
                            .then((function (token_endpoint_response) {
                                delete this.client.code;
                                delete this.client.request;
                                delete this.client.response;

                                this.fetchTokensFromIndexedDB().then((tokens) => {
                                    var currentResourceServer = localStorage.getItem("currentResourceServer");
                                    if (!tokens) {
                                        tokens = {};
                                    }
                                    if (token_endpoint_response.idToken) {
                                        tokens.idToken = token_endpoint_response.idToken;
                                    }
                                    if (this.appAuthConfig.renewStrategy === "refreshToken" && token_endpoint_response.refreshToken) {
                                        tokens.refreshToken = token_endpoint_response.refreshToken;
                                    }

                                    if (currentResourceServer !== null) {
                                        tokens[currentResourceServer] = token_endpoint_response.accessToken;
                                        localStorage.removeItem("currentResourceServer");
                                    } else {
                                        tokens.accessToken = token_endpoint_response.accessToken;
                                    }
                                    this.updateTokensInIndexedDB(tokens).then(() => resolve({
                                        claims: this.appAuthConfig.oidc ? this.getIdTokenClaims(tokens.idToken) : {},
                                        idToken: tokens.idToken,
                                        resourceServer: currentResourceServer
                                    }));
                                });
                            }).bind(this));

                    // The case when the user has returned from the authorization request with an error message
                    } else if (this.client.error) {
                        reject(this.client.error.error);

                    // The case when it doesn't appear that we have just returned from the authz request
                    } else {
                        this.fetchTokensFromIndexedDB().then((tokens) => {
                            if (tokens) {
                                resolve({
                                    idToken: tokens.idToken,
                                    claims: this.appAuthConfig.oidc ? this.getIdTokenClaims(tokens.idToken) : {}
                                });
                            } else {
                                reject("tokensUnavailable");
                            }
                        });
                    }
                }).bind(this));
            }).bind(this));
        },
        /**
         * Helper function that reduces the amount of duplicated code, as there are several different
         * places in the code that require initiating an authorization request.
         */
        authzRequest: function (client, config, extras) {
            extras = extras || {};
            var request = new AppAuth.AuthorizationRequest({
                client_id: config.clientId,
                redirect_uri: config.redirectUri,
                scope: config.scopes,
                response_type: AppAuth.AuthorizationRequest.RESPONSE_TYPE_CODE,
                // Use the config.extras as the baseline, extend with provided extras
                extras: Object.keys(extras)
                    .concat(Object.keys(config.extras || {}))
                    .reduce(function(result, key) {
                        result[key] = extras[key] || config.extras[key];
                        return result;
                    }, {})
            });

            client.authorizationHandler.performAuthorizationRequest(
                client.configuration,
                request
            );
        },
        silentAuthzRequest: function (resourceServer) {
            let config = Object.create(this.appAuthConfig);
            let authCodeGrantStrategy = () => {
                // we don't have tokens yet, but we might be in the process of obtaining them
                return this.checkForActiveAuthzRequest().then((function (hasActiveRequest) {
                    if (!hasActiveRequest) {
                        // only start a new authorization request if there isn't already an active one
                        // attempt silent authorization
                        this.authzRequest(this.client, config, { "prompt": "none" });
                    }
                    return "authCode";
                }).bind(this));
            };

            if (resourceServer) {
                localStorage.setItem("currentResourceServer", resourceServer);
                config.scopes = this.appAuthConfig.resourceServers[resourceServer];
            }

            if (config.renewStrategy === "authCode" || !resourceServer) {
                return authCodeGrantStrategy.call(this);
            } else {
                return this.fetchTokensFromIndexedDB().then((tokens) => {
                    // We can only use the refreshToken strategy if we actually have a refresh token...
                    if (tokens.refreshToken) {
                        return this.client.tokenHandler.performTokenRequest(
                            this.client.configuration,
                            new AppAuth.TokenRequest({
                                client_id: this.client.clientId,
                                redirect_uri: this.client.redirectUri,
                                grant_type: AppAuth.GRANT_TYPE_REFRESH_TOKEN,
                                refresh_token: tokens.refreshToken,
                                extras: {
                                    scope: config.scopes
                                }
                            })
                        ).then((token_endpoint_response) => {
                            // and we can only use the refreshToken strategy if using the current refresh token actually works...
                            if (token_endpoint_response.refreshToken &&
                                token_endpoint_response.accessToken) {

                                tokens.refreshToken = token_endpoint_response.refreshToken;
                                tokens[resourceServer] = token_endpoint_response.accessToken;

                                return this.updateTokensInIndexedDB(tokens)
                                    .then(() => "refreshToken");
                            } else {
                                // refresh grant didn't return tokens?
                                return authCodeGrantStrategy.call(this);
                            }
                        }, () => {
                            // refresh grant failed for some reason
                            return authCodeGrantStrategy.call(this);
                        });
                    } else {
                        // don't yet have a refresh token to use
                        return authCodeGrantStrategy.call(this);
                    }
                });
            }
        },
        getAuthzURL: function () {
            return new Promise((resolve) => {
                this.client.authorizationHandler = new AppAuth.RedirectRequestHandler(
                    // pass in a "location-like" object that resolves the promise with the url
                    void 0, void 0, { assign: resolve }
                );
                this.authzRequest(this.client, this.appAuthConfig);
            });
        },
        clearActiveAuthzRequests: function () {
            return this.checkForActiveAuthzRequest().then((function (activeRequestHandle) {
                if (activeRequestHandle) {
                    return Promise.all([
                        this.client.authorizationHandler.storageBackend.removeItem("appauth_current_authorization_request"),
                        this.client.authorizationHandler.storageBackend.removeItem(activeRequestHandle + "_appauth_authorization_request"),
                        this.client.authorizationHandler.storageBackend.removeItem(activeRequestHandle + "_appauth_authorization_service_configuration")
                    ]);
                }
            }).bind(this));
        },
        checkForActiveAuthzRequest: function () {
            return this.client.authorizationHandler
                .storageBackend.getItem("appauth_current_authorization_request");
        },
        fetchTokensFromIndexedDB: function () {
            return new Promise((resolve, reject) => {
                var dbReq = indexedDB.open("appAuth"),
                    upgradeDb = (function () {
                        return dbReq.result.createObjectStore(this.appAuthConfig.clientId);
                    }).bind(this),
                    onsuccess;
                onsuccess = () => {
                    if (!dbReq.result.objectStoreNames.contains(this.appAuthConfig.clientId)) {
                        var version = dbReq.result.version;
                        version++;
                        dbReq.result.close();
                        dbReq = indexedDB.open("appAuth", version);
                        dbReq.onupgradeneeded = upgradeDb;
                        dbReq.onsuccess = onsuccess;
                        return;
                    }
                    var objectStoreRequest = dbReq.result.transaction([this.appAuthConfig.clientId], "readonly")
                        .objectStore(this.appAuthConfig.clientId).get("tokens");
                    objectStoreRequest.onsuccess = () => {
                        var tokens = objectStoreRequest.result;
                        dbReq.result.close();
                        resolve(tokens);
                    };
                    objectStoreRequest.onerror = reject;
                };

                dbReq.onupgradeneeded = upgradeDb;
                dbReq.onsuccess = onsuccess;
                dbReq.onerror = reject;
            });
        },
        updateTokensInIndexedDB: function (tokens) {
            return new Promise((resolve, reject) => {
                var dbReq = indexedDB.open("appAuth"),
                    upgradeDb = (function () {
                        return dbReq.result.createObjectStore(this.appAuthConfig.clientId);
                    }).bind(this),
                    onsuccess;
                onsuccess = () => {
                    var objectStoreRequest = dbReq.result.transaction([this.client.clientId], "readwrite")
                        .objectStore(this.client.clientId).put(tokens, "tokens");
                    objectStoreRequest.onsuccess = () => {
                        dbReq.result.close();
                        resolve();
                    };
                    objectStoreRequest.onerror = reject;
                };

                dbReq.onupgradeneeded = upgradeDb;
                dbReq.onsuccess = onsuccess;
                dbReq.onerror = reject;
            });
        },
        /**
         * Simple jwt parsing code purely used for extracting claims.
         */
        getIdTokenClaims: function (id_token) {
            return JSON.parse(
                atob(id_token.split(".")[1].replace("-", "+").replace("_", "/"))
            );
        },
        getResourceServerFromUrl: function (url) {
            if (typeof this.appAuthConfig.resourceServers === "object" &&
                Object.keys(this.appAuthConfig.resourceServers).length) {

                return Object.keys(this.appAuthConfig.resourceServers)
                    .filter((rs) => url.indexOf(rs) === 0)[0];
            } else {
                return undefined;
            }
        },
        makeRSRequest: function (request) {
            return Promise.all([
                this.getResourceServerFromUrl(request.url),
                this.fetchTokensFromIndexedDB()
            ])
                .then((results) => {
                    var resourceServer = results[0],
                        tokens = results[1];
                    if (tokens[resourceServer]) {
                        request.options.headers["Authorization"] = `Bearer ${tokens[resourceServer]}`;
                        return request;
                    } else {
                        // There is no functional difference between a request that failed due to an invalid
                        // token and a request that was never sent because there was no token to include.
                        return Promise.reject("invalid_token");
                    }
                })
                .then((request) => fetch(request.url, request.options))
                .then((response) => {
                    if (this.getAuthHeaderDetails(response)["error"] === "invalid_token") {
                        return Promise.reject("invalid_token");
                    } else {
                        return response;
                    }
                })
                .then((response) => this.serializeResponse(response));
        },
        getAuthHeaderDetails: function (resp) {
            var authHeader = resp.headers.get("www-authenticate");

            if (!resp.ok && authHeader && authHeader.match(/^Bearer\b/)) {
                return authHeader.replace(/^Bearer\b/, "")
                    .match(/[^,=]+=".*?"/g)
                    .reduce(function (result, detail) {
                        var pair = detail.split("=");
                        result[pair[0].replace(/\s/g, "")] = pair[1].replace(/"(.*)"/, "$1");
                        return result;
                    }, {});
            } else {
                return {};
            }
        },
        serializeResponse: function (response) {
            return response.text().then((bodyText) => ({
                body: bodyText,
                init: {
                    status: response.status,
                    statusText: response.statusText,
                    headers: this.serializeHeaders(response.headers)
                }
            }));
        },
        serializeHeaders: function (headers) {
            if (!headers) { return undefined; }
            // special help for looping through iterables needed for IE
            let headersObj = {};
            let keys = headers.keys();
            let key = null;
            while (key = keys.next()) { // eslint-disable-line no-cond-assign
                if (key.done) {
                    break;
                }
                headersObj[key.value.toLowerCase()] = headers.get(key.value);
            }
            return headersObj;
        },
        logout: function () {
            return this.fetchTokensFromIndexedDB().then((function (tokens) {
                if (!tokens) {
                    return;
                }
                var revokeRequests = [];
                if (tokens.accessToken) {
                    revokeRequests.push(new AppAuth.RevokeTokenRequest({
                        client_id: this.appAuthConfig.clientId,
                        token_type_hint: "access_token",
                        token: tokens.accessToken
                    }));
                }
                if (tokens.refreshToken) {
                    revokeRequests.push(new AppAuth.RevokeTokenRequest({
                        client_id: this.appAuthConfig.clientId,
                        token_type_hint: "refresh_token",
                        token: tokens.refreshToken
                    }));
                }
                return Promise.all(
                    revokeRequests.concat(
                        Object.keys(this.appAuthConfig.resourceServers)
                            .filter(function (rs) { return !!tokens[rs]; })
                            .map((function (rs) {
                                return new AppAuth.RevokeTokenRequest({
                                    client_id: this.appAuthConfig.clientId,
                                    token_type_hint: "access_token",
                                    token: tokens[rs]
                                });
                            }).bind(this))
                    ).map((function (revokeRequest) {
                        return this.client.tokenHandler.performRevokeTokenRequest(
                            this.client.configuration,
                            revokeRequest
                        );
                    }).bind(this))
                ).then((function () {
                    if (this.appAuthConfig.oidc && tokens.idToken && this.client.configuration.endSessionEndpoint) {
                        return fetch(this.client.configuration.endSessionEndpoint + "?id_token_hint=" + tokens.idToken);
                    } else {
                        return;
                    }
                }).bind(this)).then((function () {
                    return new Promise((function (resolve, reject) {
                        var dbReq = indexedDB.open("appAuth");
                        dbReq.onsuccess = (function () {
                            var objectStoreRequest = dbReq.result.transaction([this.appAuthConfig.clientId], "readwrite")
                                .objectStore(this.appAuthConfig.clientId).clear();
                            dbReq.result.close();
                            objectStoreRequest.onsuccess = resolve;
                        }).bind(this);
                        dbReq.onerror = reject;
                    }).bind(this));
                }).bind(this));
            }).bind(this));
        }
    };

}());

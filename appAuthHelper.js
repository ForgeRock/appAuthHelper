(function () {
    "use strict";

    var AppAuth = require("@openid/appauth");

    /**
     * Module used to easily setup AppAuthJS in a way that allows it to transparently obtain and renew access tokens
     * @module AppAuthHelper
     */
    module.exports = {
        /** @function init
         * @param {Object} config - configation needed for working with the OP
         * @param {string} config.clientId - The id of this RP client within the OP
         * @param {string} config.scopes - Space-delimited list of scopes requested by this RP
         * @param {string} config.authorizationEndpoint - Full URL to the OP authorization endpoint
         * @param {string} config.tokenEndpoint - Full URL to the OP token endpoint
         * @param {string} config.revocationEndpoint - Full URL to the OP revocation endpoint
         * @param {string} config.endSessionEndpoint - Full URL to the OP end session endpoint
         * @param {array} config.resourceServers - List of strings which indicate which resource servers should automatically receive access tokens in their requests
         * @param {function} config.interactionRequiredHandler - optional function to be called anytime interaction is required. When not provided, default behavior is to redirect the current window to the authorizationEndpoint
         * @param {function} config.tokensAvailableHandler - function to be called every time tokens are available - both initially and upon renewal
         * @param {number} config.renewCooldownPeriod [1] - Minimum time (in seconds) between requests to the authorizationEndpoint for token renewal attempts
         * @param {string} config.redirectUri [appAuthHelperRedirect.html] - The redirect uri registered in the OP
         */
        init: function (config) {
            var calculatedUriLink,
                iframe = document.createElement("iframe");

            this.renewCooldownPeriod = config.renewCooldownPeriod || 1;
            this.appAuthConfig = {};
            this.tokensAvailableHandler = config.tokensAvailableHandler;
            this.interactionRequiredHandler = config.interactionRequiredHandler;

            if (!config.redirectUri) {
                calculatedUriLink = document.createElement("a");
                calculatedUriLink.href = "appAuthHelperRedirect.html";

                this.appAuthConfig.redirectUri = calculatedUriLink.href;
            } else {
                this.appAuthConfig.redirectUri = config.redirectUri;
            }

            this.appAuthConfig.resourceServers = config.resourceServers;
            this.appAuthConfig.clientId = config.clientId;
            this.appAuthConfig.scopes = config.scopes;
            this.appAuthConfig.endpoints = {
                "authorization_endpoint": config.authorizationEndpoint,
                "token_endpoint": config.tokenEndpoint,
                "revocation_endpoint": config.revocationEndpoint,
                "end_session_endpoint": config.endSessionEndpoint
            };

            window.addEventListener("message", (function (e) {
                if (e.origin !== document.location.origin) {
                    return;
                }
                switch (e.data) {
                case "appAuth-tokensAvailable":
                    var originalWindowHash = sessionStorage.getItem("originalWindowHash");
                    if (originalWindowHash !== null) {
                        window.location.hash = originalWindowHash;
                        sessionStorage.removeItem("originalWindowHash");
                    }

                    this.registerServiceWorker()
                        .then(() => this.fetchTokensFromIndexedDB())
                        .then((tokens) => this.tokensAvailableHandler(getIdTokenClaims(tokens.idToken)));

                    break;
                case "appAuth-interactionRequired":
                    if (this.interactionRequiredHandler) {
                        this.interactionRequiredHandler();
                    } else {
                        // Default behavior for when interaction is required is to redirect to the OP for login.

                        // When interaction is required, the current hash state may be lost during redirection.
                        // Save it in sessionStorage so that it can be returned to upon successfully authenticating
                        sessionStorage.setItem("originalWindowHash", window.location.hash);

                        // Use the default redirect request handler, because it will use the current window
                        // as the redirect target (rather than the hidden iframe).
                        this.client.authorizationHandler = (new AppAuth.RedirectRequestHandler());
                        authnRequest(this.client, this.appAuthConfig);
                    }

                    break;
                }
            }).bind(this), false);


            /*
             * Attach a hidden iframe onto the main document body that is used to handle
             * interaction with the token endpoint. This will allow us to perform
             * background access token renewal, in addition to handling the main PKCE-based
             * authorization code flow performed in the foreground.
             *
             * sessionStorage is used to pass the configuration down to the iframe
             */
            sessionStorage.setItem("appAuthConfig", JSON.stringify(this.appAuthConfig));

            iframe.setAttribute("src", this.appAuthConfig.redirectUri + window.location.hash);
            iframe.setAttribute("id", "AppAuthHelper");
            iframe.setAttribute("style", "display:none");
            document.getElementsByTagName("body")[0].appendChild(iframe);

            var tokenHandler;
            if (typeof Promise === "undefined" || typeof fetch === "undefined") {
                // Fall back to default, jQuery-based implementation for legacy browsers (IE).
                // Be sure jQuery is available globally if you need to support these.
                tokenHandler = new AppAuth.BaseTokenRequestHandler();
            } else {
                tokenHandler = new AppAuth.BaseTokenRequestHandler({
                    // fetch-based alternative to built-in jquery implementation
                    // TODO: replace with new AppAuth option
                    xhr: function (settings) {
                        return new Promise(function (resolve, reject) {
                            fetch(settings.url, {
                                method: settings.method,
                                body: settings.data,
                                mode: "cors",
                                cache: "no-cache",
                                headers: settings.headers
                            }).then(function (response) {
                                if (response.ok) {
                                    response.json().then(resolve);
                                } else {
                                    reject(response.statusText);
                                }
                            }, reject);
                        });
                    }
                });
            }

            this.client = {
                configuration: new AppAuth.AuthorizationServiceConfiguration(this.appAuthConfig.endpoints),
                notifier: new AppAuth.AuthorizationNotifier(),
                authorizationHandler: new AppAuth.RedirectRequestHandler(
                    // handle redirection within the hidden iframe
                    void 0, void 0, iframe.contentWindow.location
                ),
                tokenHandler: tokenHandler
            };
        },
        /**
         * Pass in a reference to an iframe element that you would like to use to handle the AS redirection,
         * rather than relying on a full-page redirection.
         */
        iframeRedirect: function (iframe) {
            // Use a provided iframe element to handle the authentication request.
            this.client.authorizationHandler = (new AppAuth.RedirectRequestHandler(
                // handle redirection within the hidden iframe
                void 0, void 0, iframe.contentWindow.location
            ));
            authnRequest(this.client, this.appAuthConfig);
        },
        /**
         * Begins process which will either get the tokens that are in session storage or will attempt to
         * get them from the OP. In either case, the tokensAvailableHandler will be called. No guarentee that the
         * tokens are still valid, however - you must be prepared to handle the case when they are not.
         */
        getTokens: function () {
            this.fetchTokensFromIndexedDB().then((tokens) => {
                if (!tokens || !tokens.accessToken || !tokens.idToken) {
                    // attempt silent authorization
                    authnRequest(this.client, this.appAuthConfig, { "prompt": "none" });
                } else {
                    this.registerServiceWorker()
                        .then(() => this.tokensAvailableHandler(getIdTokenClaims(tokens.idToken)));
                }
            });
        },
        /**
         * logout() will revoke the access token, use the id_token to end the session on the OP, clear them from the
         * local session, and finally notify the SPA that they are gone.
         */
        logout: function () {
            return this.fetchTokensFromIndexedDB().then((tokens) => {
                if (!tokens) {
                    return;
                }
                var revokeRequest = new AppAuth.RevokeTokenRequest({
                    client_id: this.appAuthConfig.clientId,
                    token: tokens.accessToken
                });
                return this.client.tokenHandler
                    .performRevokeTokenRequest(this.client.configuration, revokeRequest)
                    .then(() => fetch(this.client.configuration.endSessionEndpoint + "?id_token_hint=" + tokens.idToken))
                    .then(() => new Promise((resolve, reject) => {
                        var dbReq = indexedDB.open("appAuth",1);
                        dbReq.onsuccess = () => {
                            var objectStoreRequest = dbReq.result.transaction([this.appAuthConfig.clientId], "readwrite")
                                .objectStore(this.appAuthConfig.clientId).clear();
                            objectStoreRequest.onsuccess = resolve;
                        };
                        dbReq.onerror = reject;
                    }));
            });
        },
        renewTokens: function () {
            var timestamp = (new Date()).getTime();
            if (!this.renewTokenTimestamp || (this.renewTokenTimestamp + (this.renewCooldownPeriod*1000)) < timestamp) {
                this.renewTokenTimestamp = timestamp;
                // update reference to iframe, to ensure it is still valid
                this.client.authorizationHandler = new AppAuth.RedirectRequestHandler(
                    // handle redirection within the hidden iframe
                    void 0, void 0, document.getElementById("AppAuthHelper").contentWindow.location
                );
                authnRequest(this.client, this.appAuthConfig, { "prompt": "none" });
            }
        },
        fetchTokensFromIndexedDB: function () {
            return new Promise((resolve, reject) => {
                var dbReq = indexedDB.open("appAuth",1);
                dbReq.onupgradeneeded = () => {
                    dbReq.result.createObjectStore(this.appAuthConfig.clientId);
                };
                dbReq.onsuccess = () => {
                    var objectStoreRequest = dbReq.result.transaction([this.appAuthConfig.clientId], "readonly")
                        .objectStore(this.appAuthConfig.clientId).get("tokens");
                    objectStoreRequest.onsuccess = () => {
                        resolve(objectStoreRequest.result);
                    };
                    objectStoreRequest.onerror = reject;
                };
                dbReq.onerror = reject;
            });
        },
        registerServiceWorker: function () {
            return new Promise((resolve, reject) => {
                if ("serviceWorker" in navigator) {
                    navigator.serviceWorker.register("appAuthServiceWorker.js")
                        .then((reg) => {
                            var sendConfigMessage = () => {
                                var msg_chan = new MessageChannel();
                                msg_chan.port1.onmessage = () => {
                                    resolve();
                                };
                                reg.active.postMessage(this.appAuthConfig, [msg_chan.port2]);
                            };

                            if (reg.active) {
                                sendConfigMessage();
                            } else {
                                navigator.serviceWorker.addEventListener("controllerchange", () => {
                                    sendConfigMessage();
                                });
                            }
                        })
                        .catch(reject);
                }
            });
        }
    };

    /**
     * Helper function that reduces the amount of duplicated code, as there are several different
     * places in the code that require initiating an authorization request.
     */
    function authnRequest(client, config, extras) {
        var request = new AppAuth.AuthorizationRequest({
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            response_type: AppAuth.AuthorizationRequest.RESPONSE_TYPE_CODE,
            extras: extras || {}
        });

        client.authorizationHandler.performAuthorizationRequest(
            client.configuration,
            request
        );
    }

    /**
     * Simple jwt parsing code purely used for extracting claims.
     */
    function getIdTokenClaims(id_token) {
        return JSON.parse(
            atob(id_token.split(".")[1].replace("-", "+").replace("_", "/"))
        );
    }

}());

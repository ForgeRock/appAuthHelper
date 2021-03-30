/* global IdentityProxyXHR */

(function () {
    "use strict";

    /**
     * Module used to easily setup AppAuthJS in a way that allows it to transparently obtain and renew access tokens
     * @module AppAuthHelper
     */
    module.exports = {
        /** @function init
         * @param {Object} config - configuration needed for working with the OP
         * @param {string} config.clientId - The id of this RP client within the OP
         * @param {boolean} config.oidc [true] - indicate whether or not you want OIDC included
         * @param {string} config.authorizationEndpoint - Full URL to the OP authorization endpoint
         * @param {string} config.tokenEndpoint - Full URL to the OP token endpoint
         * @param {string} config.revocationEndpoint - Full URL to the OP revocation endpoint
         * @param {string} config.endSessionEndpoint - Full URL to the OP end session endpoint
         * @param {object} config.resourceServers - Map of resource server urls to the scopes which they require. Map values are space-delimited list of scopes requested by this RP for use with this RS
         * @param {object} config.extras -Additional parameters to include in the authorization request
         * @param {function} config.interactionRequiredHandler - optional function to be called anytime interaction is required. When not provided, default behavior is to redirect the current window to the authorizationEndpoint
         * @param {function} config.tokensAvailableHandler - function to be called every time tokens are available - both initially and upon renewal
         * @param {number} config.renewCooldownPeriod [1] - Minimum time (in seconds) between requests to the authorizationEndpoint for token renewal attempts
         * @param {string} config.redirectUri [appAuthHelperRedirect.html] - The redirect uri registered in the OP
         * @param {string} config.serviceWorkerUri [appAuthServiceWorker.js] - The path to the service worker script
         * @param {string} config.identityProxyPreference [serviceWorker] - Preferred identity proxy implementation (serviceWorker or XHR)
         * @param {string} config.renewStrategy [authCode] - Preferred access token renewal strategy (authcode or refreshToken)
         */
        init: function (config) {
            var calculatedRedirectUriLink = document.createElement("a"),
                calculatedSWUriLink = document.createElement("a"),
                promise;

            localStorage.removeItem("currentResourceServer");
            this.appAuthIframe = document.createElement("iframe");
            this.rsIframe = document.createElement("iframe");

            this.renewCooldownPeriod = config.renewCooldownPeriod || 1;
            this.appAuthConfig = {
                appLocation: document.location.href
            };
            this.tokensAvailableHandler = config.tokensAvailableHandler;
            this.interactionRequiredHandler = config.interactionRequiredHandler;
            this.appAuthConfig.oidc = typeof config.oidc !== "undefined" ? !!config.oidc : true;
            this.appAuthConfig.renewStrategy = config.renewStrategy || "authCode";
            this.pendingResourceServerRenewals = [];
            this.identityProxyPreference = config.identityProxyPreference || "serviceWorker";

            if (!config.redirectUri) {
                calculatedRedirectUriLink.href = "appAuthHelperRedirect.html";
            } else {
                calculatedRedirectUriLink.href = config.redirectUri;
            }
            this.appAuthConfig.redirectUri = calculatedRedirectUriLink.href;
            this.iframeOrigin = (new URL(this.appAuthConfig.redirectUri)).origin;

            if (!config.serviceWorkerUri) {
                calculatedSWUriLink.href = "appAuthServiceWorker.js";
            } else {
                calculatedSWUriLink.href = config.serviceWorkerUri;
            }
            this.appAuthConfig.serviceWorkerUri = calculatedSWUriLink.href;

            this.appAuthConfig.extras = config.extras || {};
            this.appAuthConfig.resourceServers = config.resourceServers || {};
            this.appAuthConfig.clientId = config.clientId;
            // get a distinct list of scopes from all resource servers
            this.appAuthConfig.scopes = Object.keys(this.appAuthConfig.resourceServers)
                .reduce((function (scopes, rs) {
                    return scopes.concat(
                        this.appAuthConfig.resourceServers[rs].split(" ").filter((function (scope) {
                            return scopes.indexOf(scope) === -1;
                        }))
                    );
                }).bind(this), this.appAuthConfig.oidc ? ["openid"] : [])
                .join(" ");

            this.appAuthConfig.endpoints = {
                "authorization_endpoint": config.authorizationEndpoint,
                "token_endpoint": config.tokenEndpoint,
                "revocation_endpoint": config.revocationEndpoint,
                "end_session_endpoint": config.endSessionEndpoint
            };

            window.addEventListener("message", (function (e) {
                if (e.origin !== this.iframeOrigin) {
                    return;
                }
                switch (e.data.message) {
                case "appAuth-tokensAvailable":
                    var originalWindowHash = localStorage.getItem("originalWindowHash-" + this.appAuthConfig.clientId);
                    if (originalWindowHash !== null) {
                        window.location.hash = originalWindowHash;
                        localStorage.removeItem("originalWindowHash-" + this.appAuthConfig.clientId);
                    }

                    // this should only be set as part of token renewal
                    if (e.data.resourceServer) {
                        localStorage.removeItem("currentResourceServer");
                        this.renewTokenTimestamp = false;

                        if (this.pendingResourceServerRenewals.length) {
                            this.pendingResourceServerRenewals.shift()();
                        }

                        this.identityProxy.tokensRenewed(e.data.resourceServer);
                    } else {
                        this.registerIdentityProxy()
                            .then((function () {
                                return this.tokensAvailableHandler(e.data.idTokenClaims);
                            }).bind(this));
                    }

                    break;
                case "appAuth-interactionRequired":
                    if (this.interactionRequiredHandler) {
                        this.interactionRequiredHandler(e.data.authorizationUrl, e.data.error);
                    } else {
                        // Default behavior for when interaction is required is to redirect to the OP for login.

                        if (window.location.hash.replace("#","").length) {
                            // When interaction is required, the current hash state may be lost during redirection.
                            // Save it in localStorage so that it can be returned to upon successfully authenticating
                            localStorage.setItem("originalWindowHash-" + this.appAuthConfig.clientId, window.location.hash);
                        }
                        window.location.href = e.data.authorizationUrl;
                    }

                    break;
                case "appAuth-logoutComplete":
                    this.logoutComplete();
                    break;
                }
            }).bind(this), false);

            /*
             * Attach two hidden iframes onto the main document body. One is used to handle
             * background token acquisition and renewal, using the AppAuth JS library. The other
             * is used to make token-bearing requests to resource server endpoints, with the help
             * of the Identity Proxy.
             */

            this.appAuthIframe.setAttribute("src", this.appAuthConfig.redirectUri);
            this.appAuthIframe.setAttribute("id", "AppAuthIframe");
            this.appAuthIframe.setAttribute("style", "display:none");

            this.rsIframe.setAttribute("src", this.appAuthConfig.redirectUri);
            this.rsIframe.setAttribute("id", "rsIframe");
            this.rsIframe.setAttribute("style", "display:none");

            this.identityProxyMessageChannel = new MessageChannel();
            this.identityProxyMessageChannel.port1.onmessage = this.handleIdentityProxyMessage.bind(this);

            promise = Promise.all([
                new Promise((function (resolve) {
                    this.rsIframe.onload = (function () {
                        this.rsIframe.onload = null;
                        resolve();
                    }).bind(this);
                }).bind(this)),
                new Promise((function (resolve) {
                    this.appAuthIframe.onload = (function () {
                        this.appAuthIframe.onload = null;
                        var mc = new MessageChannel();
                        mc.port1.onmessage = resolve;
                        this.appAuthIframe.contentWindow.postMessage({
                            message: "appAuth-config",
                            config: this.appAuthConfig
                        }, this.iframeOrigin, [mc.port2]);
                    }).bind(this);
                }).bind(this))
            ]);

            document.getElementsByTagName("body")[0].appendChild(this.appAuthIframe);
            document.getElementsByTagName("body")[0].appendChild(this.rsIframe);
            return promise;
        },
        handleIdentityProxyMessage: function (event) {
            switch (event.data.message) {
            case "makeRSRequest":
                this.rsIframe.contentWindow.postMessage(
                    {
                        request: event.data.request,
                        message: event.data.message,
                        config: this.appAuthConfig
                    },
                    this.iframeOrigin,
                    event.ports
                );
                break;
            case "renewTokens":
                this.renewTokens(event.data.resourceServer);
                break;
            }
        },

        /**
         * Begins process which will either get the tokens that are in session storage or will attempt to
         * get them from the OP. In either case, the tokensAvailableHandler will be called. No guarentee that the
         * tokens are still valid, however - you must be prepared to handle the case when they are not.
         */
        getTokens: function () {
            this.appAuthIframe.contentWindow.postMessage({
                message: "appAuth-getAvailableData",
                config: this.appAuthConfig
            }, this.iframeOrigin);
        },
        /**
         * logout() will revoke the access token, use the id_token to end the session on the OP, clear them from the
         * local session, and finally notify the SPA that they are gone.
         */
        logout: function () {
            return new Promise((function (resolve) {
                this.logoutComplete = resolve;
                this.appAuthIframe.contentWindow.postMessage({
                    message: "appAuth-logout",
                    config: this.appAuthConfig
                }, this.iframeOrigin);
            }).bind(this));
        },
        whenRenewTokenFrameAvailable: function (resourceServer) {
            return new Promise((function (resolve) {
                var currentResourceServer = localStorage.getItem("currentResourceServer");
                if (currentResourceServer === null) {
                    localStorage.setItem("currentResourceServer", resourceServer);
                    currentResourceServer = resourceServer;
                }
                if (resourceServer === currentResourceServer) {
                    resolve();
                } else {
                    this.pendingResourceServerRenewals.push(resolve);
                }
            }).bind(this));
        },
        renewTokens: function (resourceServer) {
            this.whenRenewTokenFrameAvailable(resourceServer).then((function () {
                var timestamp = (new Date()).getTime();
                localStorage.setItem("currentResourceServer", resourceServer);
                if (!this.renewTokenTimestamp || (this.renewTokenTimestamp + (this.renewCooldownPeriod*1000)) < timestamp) {
                    this.renewTokenTimestamp = timestamp;

                    this.appAuthIframe.contentWindow.postMessage({
                        message: "appAuth-getFreshAccessToken",
                        config: this.appAuthConfig,
                        resourceServer: resourceServer
                    }, this.iframeOrigin);
                }
            }).bind(this));
        },
        registerIdentityProxy: function () {
            return new Promise((function (resolve) {
                if (this.identityProxyPreference === "serviceWorker" && "serviceWorker" in navigator) {
                    var savedReg,tick;
                    var registerServiceWorker = (function() {
                        var register = navigator.serviceWorker.register(this.appAuthConfig.serviceWorkerUri);
                        register.then((function (reg) {
                            savedReg = reg;
                            navigator.serviceWorker.ready.then((function () {
                                this.identityProxyMessageChannel.port1.onmessage = (function (event) {
                                    resolve();
                                    this.handleIdentityProxyMessage.call(this, event);
                                }).bind(this);

                                reg.active.postMessage({
                                    "message": "configuration",
                                    "resourceServers": Object.keys(this.appAuthConfig.resourceServers)
                                }, [this.identityProxyMessageChannel.port2]);
                            }).bind(this));
                        }).bind(this));
                        return register;
                    }).bind(this);

                    registerServiceWorker()
                    .then((function () {
                        this.identityProxy = {
                            tokensRenewed: function (currentResourceServer) {
                                navigator.serviceWorker.controller.postMessage({
                                    "message": "tokensRenewed",
                                    "resourceServer": currentResourceServer
                                });
                            }
                        };

                        tick = setInterval((function () {
                            if (savedReg && savedReg.active) {
                                // prevents the service worker thread from becoming idle and losing
                                // the references we just passed into it.
                                savedReg.active.postMessage({"message": "keepAlive"});
                            } else {
                                // In case the service worker still somehow manages to become inactive,
                                // re-registers it.
                                registerServiceWorker().catch((function () {
                                    // somehow we stopped being able to register the service worker? Fall back to XHR in a last-ditch effort to keep working.
                                    this.registerXHRProxy();
                                    console.warn("Service worker failure, switching to XHR identity proxy");
                                    clearInterval(tick);
                                }).bind(this));
                            }
                        }).bind(this), 1000);
                    }).bind(this))
                    .catch((function () {
                        this.registerXHRProxy();
                        if (tick) {
                            clearInterval(tick);
                        }
                        resolve();
                    }).bind(this));
                } else {
                    this.registerXHRProxy();
                    resolve();
                }
            }).bind(this));
        },
        registerXHRProxy: function () {
            if (typeof IdentityProxyXHR !== "undefined") {
                this.identityProxy = new IdentityProxyXHR(
                    Object.keys(this.appAuthConfig.resourceServers),
                    this.identityProxyMessageChannel.port2
                );
            } else {
                throw "Browser incompatible with this build of AppAuthHelper. Use the legacy 'compatible' build instead.";
            }
        }
    };

}());

/* global IdentityProxyXHR */

(function () {
    "use strict";
    var appConfigs = {};
    var PRIMARY_AUTH_ID = "Primary";
    var identityProxy;

    /**
     * Module used to easily setup AppAuthJS in a way that allows it to transparently obtain and renew access tokens
     * @module AppAuthHelper
     */
    module.exports = {
        /** @function init
         * @param {Object} config - configuration needed for working with the OP
         * @param {string} config.clientId - The id of this RP client within the OP
         * @param {string} [config.authId] - The unique id to identify this config and any associated requests
         * @param {boolean} [config.oidc=true] - indicate whether or not you want OIDC included
         * @param {string} config.authorizationEndpoint - Full URL to the OP authorization endpoint
         * @param {string} config.tokenEndpoint - Full URL to the OP token endpoint
         * @param {string} config.revocationEndpoint - Full URL to the OP revocation endpoint
         * @param {string} config.endSessionEndpoint - Full URL to the OP end session endpoint
         * @param {object} config.resourceServers - Map of resource server urls to the scopes which they require. Map values are space-delimited list of scopes requested by this RP for use with this RS
         * @param {object} [config.extras] -Additional parameters to include in the authorization request
         * @param {function} [config.interactionRequiredHandler] - optional function to be called anytime interaction is required. When not provided, default behavior is to redirect the current window to the authorizationEndpoint
         * @param {function} config.tokensAvailableHandler - function to be called once tokens are available - either from the browser storage or newly fetched.
         * @param {number} [config.renewCooldownPeriod=1] - Minimum time (in seconds) between requests to the authorizationEndpoint for token renewal attempts
         * @param {string} [config.redirectUri=appAuthHelperRedirect.html] - The redirect uri registered in the OP
         * @param {string} [config.serviceWorkerUri=appAuthServiceWorker.js] - The path to the service worker script
         * @param {string} [config.identityProxyPreference=serviceWorker] - Preferred identity proxy implementation (serviceWorker or XHR)
         * @param {string} [config.renewStrategy=authCode] - Preferred access token renewal strategy (authcode or refreshToken)
         */
        init: function (config) {
            // NOTE: create a new one if no index is given
            const authId = config.authId || PRIMARY_AUTH_ID;

            appConfigs[authId] = {};
            var calculatedRedirectUriLink = document.createElement("a"),
                calculatedSWUriLink = document.createElement("a"),
                promise;

            localStorage.removeItem("currentResourceServer");
            appConfigs[authId].appAuthIframe = document.createElement("iframe");
            appConfigs[authId].rsIframe = document.createElement("iframe");

            appConfigs[authId].renewCooldownPeriod = config.renewCooldownPeriod || 1;
            appConfigs[authId].appAuthConfig = {
                // discard the &loggedin=true part that might be included by us
                appLocation: document.location.href.replace(/#?&loggedin=true$/, ""),
                appHostname: new URL(config.authorizationEndpoint).host,
                authId,
            };
            appConfigs[authId].tokensAvailableHandler = config.tokensAvailableHandler;
            appConfigs[authId].interactionRequiredHandler = config.interactionRequiredHandler;
            appConfigs[authId].appAuthConfig.oidc = typeof config.oidc !== "undefined" ? !!config.oidc : true;
            appConfigs[authId].appAuthConfig.renewStrategy = config.renewStrategy || "authCode";
            appConfigs[authId].pendingResourceServerRenewals = [];
            appConfigs[authId].identityProxyPreference = config.identityProxyPreference || "serviceWorker";

            if (!config.redirectUri) {
                calculatedRedirectUriLink.href = "appAuthHelperRedirect.html";
            } else {
                calculatedRedirectUriLink.href = config.redirectUri;
            }
            appConfigs[authId].appAuthConfig.redirectUri = calculatedRedirectUriLink.href;
            appConfigs[authId].iframeOrigin = (new URL(appConfigs[authId].appAuthConfig.redirectUri)).origin;

            if (!config.serviceWorkerUri) {
                calculatedSWUriLink.href = "appAuthServiceWorker.js";
            } else {
                calculatedSWUriLink.href = config.serviceWorkerUri;
            }
            appConfigs[authId].appAuthConfig.serviceWorkerUri = calculatedSWUriLink.href;

            appConfigs[authId].appAuthConfig.extras = config.extras || {};
            appConfigs[authId].appAuthConfig.resourceServers = config.resourceServers || {};
            appConfigs[authId].appAuthConfig.clientId = config.clientId;
            // get a distinct list of scopes from all resource servers
            appConfigs[authId].appAuthConfig.scopes = Object.keys(appConfigs[authId].appAuthConfig.resourceServers)
                .reduce((function (scopes, rs) {
                    return scopes.concat(
                        appConfigs[authId].appAuthConfig.resourceServers[rs].split(" ").filter((function (scope) {
                            return scopes.indexOf(scope) === -1;
                        }))
                    );
                }).bind(this), appConfigs[authId].appAuthConfig.oidc ? ["openid"] : [])
                .join(" ");

            appConfigs[authId].appAuthConfig.endpoints = {
                "authorization_endpoint": config.authorizationEndpoint,
                "token_endpoint": config.tokenEndpoint,
                "revocation_endpoint": config.revocationEndpoint,
                "end_session_endpoint": config.endSessionEndpoint
            };

            window.removeEventListener("message", this.windowListener, false);
            window.addEventListener("message", this.windowListener, false);

            /*
             * Attach two hidden iframes onto the main document body. One is used to handle
             * background token acquisition and renewal, using the AppAuth JS library. The other
             * is used to make token-bearing requests to resource server endpoints, with the help
             * of the Identity Proxy.
             */

            appConfigs[authId].appAuthIframe.setAttribute("src", appConfigs[authId].appAuthConfig.redirectUri);
            appConfigs[authId].appAuthIframe.setAttribute("id", `AppAuthIframe-${authId}`);
            appConfigs[authId].appAuthIframe.setAttribute("style", "display:none");

            appConfigs[authId].rsIframe.setAttribute("src", appConfigs[authId].appAuthConfig.redirectUri);
            appConfigs[authId].rsIframe.setAttribute("id", `rsIframe-${authId}`);
            appConfigs[authId].rsIframe.setAttribute("style", "display:none");

            appConfigs[authId].identityProxyMessageChannel = new MessageChannel();
            appConfigs[authId].identityProxyMessageChannel.port1.onmessage = this.handleIdentityProxyMessage.bind(appConfigs[authId]);

            promise = Promise.all([
                new Promise((function (resolve) {
                    appConfigs[authId].rsIframe.onload = (function () {
                        appConfigs[authId].rsIframe.onload = null;
                        resolve();
                    }).bind(appConfigs[authId]);
                }).bind(appConfigs[authId])),
                new Promise((function (resolve) {
                    appConfigs[authId].appAuthIframe.onload = (function () {
                        appConfigs[authId].appAuthIframe.onload = null;
                        var mc = new MessageChannel();
                        mc.port1.onmessage = resolve;
                        appConfigs[authId].appAuthIframe.contentWindow.postMessage({
                            message: "appAuth-config",
                            config: this.appAuthConfig
                        }, appConfigs[authId].iframeOrigin, [mc.port2]);
                    }).bind(appConfigs[authId]);
                }).bind(appConfigs[authId]))
            ]);

            document.getElementsByTagName("body")[0].appendChild(appConfigs[authId].appAuthIframe);
            document.getElementsByTagName("body")[0].appendChild(appConfigs[authId].rsIframe);

            // must be this because only one proxy exists
            appConfigs[authId].registerIdentityProxy = this.registerIdentityProxy;
            appConfigs[authId].registerXHRProxy = this.registerXHRProxy.bind(this);
            appConfigs[authId].renewTokens = this.renewTokens.bind(appConfigs[authId]);
            appConfigs[authId].whenRenewTokenFrameAvailable = this.whenRenewTokenFrameAvailable.bind(appConfigs[authId]);
            appConfigs[authId].logout = this.logout;

            return promise;
        },
        windowListener: function (e) {
            let scopeAuthId = e.data && e.data.authId ? e.data.authId: PRIMARY_AUTH_ID;
            if (!appConfigs[scopeAuthId]) {
                return;
            }
            if (e.origin !== appConfigs[scopeAuthId].iframeOrigin) {
                return;
            }
            switch (e.data.message) {
            case "appAuth-tokensAvailable":

                // this should only be set as part of token renewal
                if (e.data.resourceServer) {
                    localStorage.removeItem("currentResourceServer");
                    appConfigs[scopeAuthId].renewTokenTimestamp = false;

                    if (appConfigs[scopeAuthId].pendingResourceServerRenewals.length) {
                        appConfigs[scopeAuthId].pendingResourceServerRenewals.shift()();
                    }

                    identityProxy.tokensRenewed(e.data.resourceServer);
                } else {
                    var originalWindowHash = localStorage.getItem("originalWindowHash-" + scopeAuthId),
                        returnedFromLogin = !!window.location.hash.match(/&loggedin=true$/);

                    if (originalWindowHash === null || originalWindowHash === "" || originalWindowHash === "#") {
                        history.replaceState(undefined, undefined, window.location.href.replace(/#&loggedin=true$/, ""));
                    } else {
                        history.replaceState(undefined, undefined, "#" + originalWindowHash.replace("#", ""));
                    }

                    localStorage.removeItem("originalWindowHash-" + scopeAuthId);

                    appConfigs[scopeAuthId].registerIdentityProxy(scopeAuthId)
                        .then((function () {
                            return appConfigs[scopeAuthId].tokensAvailableHandler(e.data.idTokenClaims, e.data.idToken, returnedFromLogin);
                        }).bind(appConfigs[scopeAuthId]));
                }

                break;
            case "appAuth-interactionRequired":
                if (appConfigs[scopeAuthId].interactionRequiredHandler) {
                    appConfigs[scopeAuthId].interactionRequiredHandler(e.data.authorizationUrl, e.data.error);
                } else {
                    // Default behavior for when interaction is required is to redirect to the OP for login.

                    // When interaction is required, the current hash state may be lost during redirection.
                    // Save it in localStorage so that it can be returned to upon successfully authenticating
                    localStorage.setItem("originalWindowHash-" + scopeAuthId, window.location.hash);
                    window.location.href = e.data.authorizationUrl;
                }

                break;
            case "appAuth-logoutComplete":
                appConfigs[scopeAuthId].logoutComplete();
                break;
            }
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
         * get them from the OP. In either case, the tokensAvailableHandler will be called. No guarantee that the
         * tokens are still valid, however - you must be prepared to handle the case when they are not.
         */
        getTokens: function (authIds) {
            var iterate = authIds || [PRIMARY_AUTH_ID];
            iterate.forEach(function(authId) {
                appConfigs[authId].appAuthIframe.contentWindow.postMessage({
                    message: "appAuth-getAvailableData",
                    config: appConfigs[authId].appAuthConfig
                }, appConfigs[authId].iframeOrigin);
            });
        },

        /**
         * logout() will revoke the access token, use the id_token to end the session on the OP, clear them from the
         * local session, and finally notify the SPA that they are gone.
         */
        logout: function (options, authIds) {
            function logoutAndReset (authId) {
                options = options || {};
                options.revoke_tokens = options.revoke_tokens!==false;
                options.end_session = options.end_session!==false;
                return new Promise((function (resolve) {
                    if(authId === PRIMARY_AUTH_ID) {
                        appConfigs[authId].logoutComplete = resolve;
                    } else {
                        appConfigs[authId].logoutComplete = () => {
                            // cleanup for secondary configs
                            identityProxy.removeProxyCore(appConfigs[authId].appAuthConfig.appHostname);
                            delete appConfigs[authId];
                            document.getElementById(`AppAuthIframe-${authId}`).remove();
                            document.getElementById(`rsIframe-${authId}`).remove();
                            resolve();
                        };
                    }
                    appConfigs[authId].appAuthIframe.contentWindow.postMessage({
                        message: "appAuth-logout",
                        config: appConfigs[authId].appAuthConfig,
                        options: options
                    }, appConfigs[authId].iframeOrigin);
                }).bind(this));
            }

            // Remove the primary auth ID because we need to sign out of it after all the other ones to have proper clean up
            var allSecondary = authIds || Object.keys(appConfigs).filter((authId) => authId !== PRIMARY_AUTH_ID);
            return Promise.all(
                allSecondary.map(
                    (logoutAndReset).bind(this)
                )).then(function () {
                if (authIds === undefined || authIds[0] === PRIMARY_AUTH_ID){
                    return logoutAndReset(PRIMARY_AUTH_ID);
                }
            });
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
        registerIdentityProxy: function (authId) {
            return new Promise((function (resolve) {
                if (this.identityProxyPreference === "serviceWorker" && "serviceWorker" in navigator) {
                    var savedReg;
                    var tick;
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

                    registerServiceWorker().then((function () {
                        identityProxy = {
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
                                    // eslint-disable-next-line no-console
                                    console.warn("Service worker failure, switching to XHR identity proxy");
                                    clearInterval(tick);
                                }).bind(this));
                            }
                        }).bind(this), 1000);
                    }).bind(this)).catch((function () {
                        this.registerXHRProxy();
                        if (tick) {
                            clearInterval(tick);
                        }
                        resolve();
                    }).bind(this));
                } else {
                    this.registerXHRProxy(authId);
                    resolve();
                }
            }).bind(this));
        },
        registerXHRProxy: function (authId) {
            if (typeof IdentityProxyXHR !== "undefined") {
                if (identityProxy) {
                    identityProxy.addProxyCore(
                        Object.keys(appConfigs[authId].appAuthConfig.resourceServers),
                        appConfigs[authId].identityProxyMessageChannel.port2,
                        appConfigs[authId].appAuthConfig.appHostname,
                    );
                } else {
                    identityProxy = new IdentityProxyXHR(
                        Object.keys(appConfigs[authId].appAuthConfig.resourceServers),
                        appConfigs[authId].identityProxyMessageChannel.port2,
                        appConfigs[authId].appAuthConfig.appHostname,
                    );
                }
            } else {
                throw "Browser incompatible with this build of AppAuthHelper. Use the legacy 'compatible' build instead.";
            }
        }
    };

}());

/* global TRUSTED_ORIGIN */

(function () {
    "use strict";

    // appAuth expects the details to be provided via hash, so copy them there
    window.location.hash = window.location.search.substring(1); // removes the '?'
    var appAuthConfig;

    if (window.location.search) {
        const params = new URLSearchParams(window.location.search);
        const iss = params.get("iss");
        const error = params.get("error");
        const getMatchingAppAuthConfig = ((domainToMatch) => {
            for (let key = 0; key < localStorage.length; key++ ) {
                const itemName = localStorage.key(key);
                if (itemName.includes("appAuthConfig-")) {
                    const appAuthConfig = JSON.parse(localStorage.getItem(itemName));
                    const match = appAuthConfig && domainToMatch === appAuthConfig.appHostname;
                    if (match) {
                        return appAuthConfig;
                    }
                }
            }
        });
        if (iss){
            const domain = new URL(iss).host;
            appAuthConfig = getMatchingAppAuthConfig(domain);
        } else if (error && error === "interaction_required") {
            appAuthConfig = getMatchingAppAuthConfig(window.location.host);
        }
    }

    var TokenManager = require("./TokenManager");
    // var tokenManager;
    var tokenManagerInstance;
    // don't trigger any default token management behavior unless
    // we have some parameters to process
    if (appAuthConfig && window.location.hash.replace("#","").length) {
        tokenManagerInstance = new TokenManager(appAuthConfig);
        tokenManagerInstance.getAvailableData()
            .then((data) => {
                // We succeeded, so we don't need to retain any hash details.
                window.location.hash = "";
                parent.postMessage({
                    message: "appAuth-tokensAvailable",
                    resourceServer: data.resourceServer,
                    idTokenClaims: data.claims,
                    idToken: data.idToken,
                    authId: appAuthConfig.authId
                }, TRUSTED_ORIGIN);
            },
            (error) => {
                // When an error is returned, we need to report that to
                // the parent frame along with the url that the user needs to
                // visit and the specific error code.
                tokenManagerInstance.getAuthzURL().then((url) => {
                    return parent.postMessage({
                        message: "appAuth-interactionRequired",
                        error: error,
                        authorizationUrl: url,
                        authId: appAuthConfig.authId
                    }, TRUSTED_ORIGIN);
                });
            })
            .finally(() => {
                // if we are running in the context of a full window (rather than an iframe)
                if (!parent.document.getElementById(`AppAuthIframe-${appAuthConfig.authId}`)) {
                    setTimeout(() => {
                        var appLocation = document.createElement("a");
                        appLocation.href = appAuthConfig.appLocation || ".";
                        appLocation.hash = appLocation.hash + "&loggedin=true";
                        window.location.assign(appLocation.href);
                    }, 0);
                }
            });
    }

    // will receive these messages when running in an iframe
    window.addEventListener("message", function (e) {
        if (e.origin !== TRUSTED_ORIGIN) {
            return;
        }
        
        var authId = e.data.config.authId;
        tokenManagerInstance = tokenManagerInstance || new TokenManager(e.data.config);

        switch (e.data.message) {
        case "appAuth-config":
            localStorage.setItem(`appAuthConfig-${authId}`, JSON.stringify(e.data.config));
            // There normally shouldn't be an active authorization request going on when the
            // config is first passed in here. Just in case we somehow got here with a
            // remnant left over, clean it out.
            tokenManagerInstance.clearActiveAuthzRequests().then(() => {
                return e.ports[0].postMessage("configured");
            });
            break;
        case "appAuth-logout":
            tokenManagerInstance.logout(e.data.options).then(() => {
                localStorage.removeItem(`appAuthConfig-${authId}`);
                parent.postMessage({
                    message: "appAuth-logoutComplete",
                    authId,
                }, TRUSTED_ORIGIN);
            });
            break;
        case "appAuth-getFreshAccessToken":
            tokenManagerInstance.silentAuthzRequest(e.data.resourceServer).then((strategyUsed) => {
                if (strategyUsed === "refreshToken") {
                    parent.postMessage({
                        message: "appAuth-tokensAvailable",
                        resourceServer: e.data.resourceServer,
                        authId,
                    }, TRUSTED_ORIGIN);
                }
            });
            break;
        case "appAuth-getAvailableData":
            tokenManagerInstance.getAvailableData()
                .then((data) => {
                    parent.postMessage({
                        message: "appAuth-tokensAvailable",
                        idTokenClaims: data.claims,
                        idToken: data.idToken,
                        authId,
                    }, TRUSTED_ORIGIN);
                }, () => {
                    tokenManagerInstance.silentAuthzRequest();
                });
            break;
        case "makeRSRequest":
            tokenManagerInstance.makeRSRequest(e.data.request)
                .then(
                    (response) => {
                        return e.ports[0].postMessage({response});},
                    (error) => {
                        return e.ports[0].postMessage({error});
                    }
                );
            break;
        }
    });
}());

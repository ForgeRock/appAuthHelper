/* global TRUSTED_ORIGIN */

(function () {
    "use strict";

    // appAuth expects the details to be provided via hash, so copy them there
    window.location.hash = window.location.search.substring(1); // removes the '?'

    var appAuthConfig = JSON.parse(localStorage.getItem("appAuthConfig")),
        TokenManager = require("./TokenManager"),
        tokenManager;

    // don't trigger any default token management behavior unless
    // we have some parameters to process
    if (appAuthConfig && window.location.hash.replace("#","").length) {
        tokenManager = new TokenManager(appAuthConfig);
        tokenManager.getAvailableData()
            .then((data) => {
                // We succeeded, so we don't need to retain any hash details.
                window.location.hash = "";
                parent.postMessage({
                    message: "appAuth-tokensAvailable",
                    idTokenClaims: data.claims,
                    resourceServer: data.resourceServer
                }, TRUSTED_ORIGIN);
            },
            (error) => {
                // When an error is returned, we need to report that to
                // the parent frame along with the url that the user needs to
                // visit and the specific error code.
                tokenManager.getAuthzURL().then((url) =>
                    parent.postMessage({
                        message: "appAuth-interactionRequired",
                        error: error,
                        authorizationUrl: url
                    }, TRUSTED_ORIGIN)
                );
            })
            .finally(() => {
                // if we are running in the context of a full window (rather than an iframe)
                if (!parent.document.getElementById('AppAuthIframe')) {
                    setTimeout(() => {
                        var appLocation = document.createElement("a");
                        appLocation.href = appAuthConfig.appLocation || ".";
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

        tokenManager = tokenManager || new TokenManager(e.data.config);
        switch (e.data.message) {
        case "appAuth-config":
            localStorage.setItem("appAuthConfig", JSON.stringify(e.data.config));
            // There normally shouldn't be an active authorization request going on when the
            // config is first passed in here. Just in case we somehow got here with a
            // remnant left over, clean it out.
            tokenManager.clearActiveAuthzRequests().then(() =>
                e.ports[0].postMessage("configured")
            );
            break;
        case "appAuth-logout":
            tokenManager.logout().then(() => {
                parent.postMessage({
                    message: "appAuth-logoutComplete"
                }, TRUSTED_ORIGIN);
            });
            break;
        case "appAuth-getFreshAccessToken":
            tokenManager.silentAuthzRequest(e.data.resourceServer).then((strategyUsed) => {
                if (strategyUsed === "refreshToken") {
                    parent.postMessage({
                        message: "appAuth-tokensAvailable",
                        resourceServer: e.data.resourceServer
                    }, TRUSTED_ORIGIN);
                }
            });
            break;
        case "appAuth-getAvailableData":
            tokenManager.getAvailableData()
                .then((data) => {
                    parent.postMessage({
                        message: "appAuth-tokensAvailable",
                        idTokenClaims: data.claims
                    }, TRUSTED_ORIGIN);
                }, () => {
                    tokenManager.silentAuthzRequest();
                });
            break;
        case "makeRSRequest":
            tokenManager.makeRSRequest(e.data.request)
                .then(
                    (response) => e.ports[0].postMessage({response}),
                    (error) => e.ports[0].postMessage({error})
                );
            break;
        }
    });

}());

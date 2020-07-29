(function () {
    "use strict";

    var IdentityProxyCore = require("./IdentityProxyCore"),
        IdentityProxyXHR = function () {
            var _this = this,
                RealXHROpen = XMLHttpRequest.prototype.open,
                RealXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader,
                RealXHRGetAllResponseHeaders = XMLHttpRequest.prototype.getAllResponseHeaders,
                RealXHRGetResponseHeader = XMLHttpRequest.prototype.getResponseHeader,
                RealXHRSend = XMLHttpRequest.prototype.send;

            /**
             * Override default methods for all XHR requests in order to add
             * access tokens and intercept invalid_token failures
             */
            XMLHttpRequest.prototype.open = function (method, url, isAsync) {
                if (typeof isAsync !== "undefined" && !isAsync) {
                    throw "Synchronous XHR requests not supported";
                }

                var calculatedUriLink = document.createElement("a");
                calculatedUriLink.href = url;

                this.url = calculatedUriLink.href;
                this.method = method;
                return RealXHROpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.setRequestHeader = function (header, value) {
                this.headers = this.headers || {};
                header = header.toLowerCase();
                this.headers[header] = this.headers[header] ? `${this.headers[header]},${value}` : value;
                return RealXHRSetRequestHeader.call(this, header, value);
            };
            XMLHttpRequest.prototype.send = function (body) {
                this.headers = this.headers || {};
                if (this.headers["x-appauthhelper-anonymous"] === "true") {
                    this.customResponse = false;
                    RealXHRSend.call(this, body);
                    return;
                }
                var resourceServer = _this.getResourceServerFromUrl(this.url);
                if (resourceServer && !this.headers["authorization"]) {
                    this.customResponse = true;
                    _this.interceptRequest({
                        xhr: this,
                        body: body
                    }, resourceServer).then(() => {
                        // explicitly set the response details
                        Object.defineProperty(this, "readyState", {
                            "get": function () {
                                return 4; // DONE
                            }
                        });
                        Object.defineProperty(this, "status", {
                            "get": function () {
                                return _this.response.init.status;
                            }
                        });
                        Object.defineProperty(this, "statusText", {
                            "get": function () {
                                return _this.response.init.statusText;
                            }
                        });
                        Object.defineProperty(this, "responseText", {
                            "get": function () {
                                return _this.response.body;
                            }
                        });

                        Object.defineProperty(this, "response", {
                            "get": function () {
                                switch (this.responseType) {
                                case "json":
                                    try {
                                        return JSON.parse(this.responseText);
                                    } catch (e) {
                                        return null;
                                    }
                                case "document":
                                    return (new DOMParser()).parseFromString(this.responseText, "application/xml");
                                default:
                                    return this.responseText;
                                }
                            }
                        });
                        Object.defineProperty(this, "responseXML", {
                            "get": function () {
                                return this.response;
                            }
                        });

                        // fire whatever events are registered
                        this.onload && this.onload();
                        this.onloadend && this.onloadend();
                        this.onreadystatechange && this.onreadystatechange();
                    });
                } else {
                    this.customResponse = false;
                    RealXHRSend.call(this, body);
                }
            };
            XMLHttpRequest.prototype.getAllResponseHeaders = function () {
                if (this.customResponse) {
                    return Object.keys(_this.response.init.headers)
                        .reduce((result, key) =>
                            result.concat(`${key}: ${_this.response.init.headers[key]}\r\n`)
                        , "");
                } else {
                    return RealXHRGetAllResponseHeaders.call(this);
                }
            };
            XMLHttpRequest.prototype.getResponseHeader = function (headerName) {
                if (this.customResponse) {
                    return _this.response.init.headers[headerName.toLowerCase()] || null;
                } else {
                    return RealXHRGetResponseHeader.call(this, headerName);
                }
            };
            return IdentityProxyCore.apply(this, arguments);
        };
    IdentityProxyXHR.prototype = Object.create(IdentityProxyCore.prototype);

    IdentityProxyXHR.prototype.tokensRenewed = function (currentResourceServer) {
        this.retryFailedRequests(currentResourceServer);
    };

    IdentityProxyXHR.prototype.serializeRequest = function (request) {
        return new Promise((resolve) => {
            new Request(request.xhr.url, {
                method: request.xhr.method,
                headers: request.xhr.headers,
                body: ["GET","HEAD"].indexOf(request.xhr.method.toUpperCase()) === -1 && request.body ? request.body : undefined,
                credentials: request.xhr.withCredentials ? "include" : "omit"
            }).blob()
            .then((bodyBlob) => this.fixupBlobContentType(bodyBlob))
            .then((bodyBlob) =>
                resolve({
                    url: request.xhr.url,
                    options: {
                        method: request.xhr.method,
                        headers: request.xhr.headers,
                        body: ["GET","HEAD"].indexOf(request.xhr.method.toUpperCase()) === -1 && bodyBlob && bodyBlob.size ? bodyBlob : undefined,
                        credentials: request.xhr.withCredentials ? "include" : "omit"
                    }
                })
            );
        });
    };

    IdentityProxyXHR.prototype.deserializeResponse = function (serializedResponse) {
        this.response = serializedResponse;
        return Promise.resolve(this.response);
    };

    module.exports = IdentityProxyXHR;
}());

window.Promise = window.Promise || (typeof require("promise-polyfill") === "function" ? require("promise-polyfill") : require("promise-polyfill").default);
require("url-polyfill");
window.IdentityProxyXHR = require("./IdentityProxyXHR");

module.exports = require("./appAuthHelper");

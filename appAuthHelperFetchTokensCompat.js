window.Promise = window.Promise || require("promise-polyfill");
window.fetch = window.fetch || require("whatwg-fetch").fetch;
require("url-polyfill");
require("webcrypto-shim");
String.prototype.includes = String.prototype.includes || (function (substr) { return this.indexOf(substr) !== -1; });

require("./appAuthHelperFetchTokens");

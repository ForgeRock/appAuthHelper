const IdentityProxyServiceWorker = require("../IdentityProxyServiceWorker");

describe("IdentityProxyServiceWorker", () => {
    it("has the expected shape", () => {
        const resourceServers = ["https://test.com"];
        const transmissionPort = {
            postMessage: _ => _
        };
		
        expect(new IdentityProxyServiceWorker(resourceServers, transmissionPort)).toMatchSnapshot();
    });	
});
const IdentityProxyXHR = require("../IdentityProxyXHR");

describe("IdentityProxyXHR", () => {
    it("has the expected shape", () => {
        const resourceServers = ["https://test.com"];
        const transmissionPort = {
            postMessage: _ => _
        };
		
        expect(new IdentityProxyXHR(resourceServers, transmissionPort)).toMatchSnapshot();
    });	
});
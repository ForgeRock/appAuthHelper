const IdentityProxyCore = require("../IdentityProxyCore");

describe("IdentityProxyCore", () => {
    it("has the expected shape", () => {
        const resourceServers = ["https://test.com"];
        const transmissionPort = {
            postMessage: _ => _
        };
		
        expect(new IdentityProxyCore(resourceServers, transmissionPort)).toMatchSnapshot();
    });	
});
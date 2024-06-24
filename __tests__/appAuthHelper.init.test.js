const appAuthHelper = require("../appAuthHelper");

// Mock MessageChannel
window.MessageChannel = require("worker_threads").MessageChannel;

describe("appAuthHelper.init", () => {
    it("returns a promise", () => {
        expect(appAuthHelper.init({}) instanceof Promise).toBe(true);
    });	

    it("creates rsIframe and AppAuthIframe", () => {
        appAuthHelper.init({});        
        const rsIframe = document.getElementById("rsIframe");
        const AppAuthIframe = document.getElementById("AppAuthIframe");

        expect(rsIframe).toBeDefined();
        expect(AppAuthIframe).toBeDefined();
    });

    it("should clear currentResourceServer from local storage", () => {
        localStorage.setItem("currentResourceServer", "test");
        appAuthHelper.init({});        
        expect(localStorage.getItem("currentResourceServer")).toBe(null);
    });

    // It is currently not possible to test the rest of this without some refactoring as it relies on the iframes being properly served and configured.
});

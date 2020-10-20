describe("appAuthHelperFetchTokens", () => {
    it('reads from localStorage', () => {
        const localStorageGetSpy = jest.spyOn(window.localStorage.__proto__, 'getItem');
        
        require("../appAuthHelperFetchTokens");

        expect(localStorageGetSpy).toBeCalledTimes(1);
        expect(localStorageGetSpy).toBeCalledWith("appAuthConfig");
    });
});
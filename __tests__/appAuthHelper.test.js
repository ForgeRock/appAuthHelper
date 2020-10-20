const appAuthHelper = require("../appAuthHelper");

test("appAuthHelper has the expected shape", () => {
    expect(appAuthHelper).toMatchSnapshot();
});
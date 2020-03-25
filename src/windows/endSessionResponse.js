var OidcConstants = require("./oidcConstants");

var EXPECTED_QUERY_KEYS = [
    OidcConstants.QUERY_KEY_STATE
];

function EndSessionResponse(responseUrl, request) {
    var query = responseUrl.searchParams;
    var additionalParameters = {};
    query.forEach(function (value, key) {
        if (EXPECTED_QUERY_KEYS.indexOf(key) < 0) additionalParameters[key] = value;
    });
    this.request = request;
    this.state = query.get(OidcConstants.QUERY_KEY_STATE);
    this.additionalParameters = additionalParameters;
}
exports.EndSessionResponse = EndSessionResponse;

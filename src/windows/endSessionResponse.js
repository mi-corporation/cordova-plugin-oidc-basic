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

EndSessionResponse.validateResponse = function (responseUrl, request, errors) {
    var initLength = errors.length;
    var query = responseUrl.searchParams;

    // Validate that returned state matches the value from the request, for parity with
    // AppAuth-iOS.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationService.m
    // (search "OIDErrorCodeOAuthAuthorizationClientError").
    var responseState = query.get(OidcConstants.QUERY_KEY_STATE);
    if (request.state !== responseState) {
        errors.push("State mismatch, expecting " + request.state + " but got " + responseState);
    }

    return errors.length === initLength;
};

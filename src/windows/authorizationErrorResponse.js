var OidcConstants = require("./oidcConstants");

function AuthorizationErrorResponse(responseUrl, request) {
    var query = responseUrl.searchParams;
    this.request = request;
    this.error = query.get(OidcConstants.QUERY_KEY_ERROR);
    this.errorDescription = query.get(OidcConstants.QUERY_KEY_ERROR_DESCRIPTION);
    this.errorUrl = query.get(OidcConstants.QUERY_KEY_ERROR_URI);
    this.state = query.get(OidcConstants.QUERY_KEY_STATE);
}
exports.AuthorizationErrorResponse = AuthorizationErrorResponse;

AuthorizationErrorResponse.isErrorResponse = function (responseUrl) {
    // Providers are required to set the error query string key in case of errors.
    // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    return !!responseUrl.searchParams.get(OidcConstants.QUERY_KEY_ERROR);
};

AuthorizationErrorResponse.validateResponse = function (responseUrl, request, errors) {
    var initLength = errors.length;
    var query = responseUrl.searchParams;

    // Validate that returned state matches the value from the request.
    // We do this for error responses as well as for success responses
    // to defend against the possibility that an attacker might try to
    // inject a mock error response. This matches the behavior of e.g.
    // AppAuth-JS (https://github.com/openid/AppAuth-JS).
    // See https://github.com/openid/AppAuth-JS/blob/master/src/redirect_based_handler.ts
    var responseState = query.get(OidcConstants.QUERY_KEY_STATE);
    if (request.state !== responseState) {
        errors.push("State mismatch, expecting " + request.state + " but got " + responseState);
    }

    return errors.length === initLength;
};

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

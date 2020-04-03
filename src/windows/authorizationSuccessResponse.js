var OidcConstants = require("./oidcConstants");

var EXPECTED_QUERY_KEYS = [
    OidcConstants.QUERY_KEY_CODE,
    OidcConstants.QUERY_KEY_STATE,
    OidcConstants.QUERY_KEY_EXPIRES_IN,
    OidcConstants.QUERY_KEY_TOKEN_TYPE,
    OidcConstants.QUERY_KEY_ID_TOKEN,
    OidcConstants.QUERY_KEY_SCOPE
];

function AuthorizationSuccessResponse(responseUrl, request) {
    // Cf https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationResponse.m
    var query = responseUrl.searchParams;
    var additionalParameters = {};
    query.forEach(function (value, key) {
        if (EXPECTED_QUERY_KEYS.indexOf(key) < 0) additionalParameters[key] = value;
    });
    this.request = request;
    this.authorizationCode = query.get(OidcConstants.QUERY_KEY_CODE);
    this.state = query.get(OidcConstants.QUERY_KEY_STATE);
    this.accessToken = query.get(OidcConstants.QUERY_KEY_ACCESS_TOKEN);
    this.accessTokenExpirationDate = computeExpirationDate(query.get(OidcConstants.QUERY_KEY_EXPIRES_IN));
    this.tokenType = query.get(OidcConstants.QUERY_KEY_TOKEN_TYPE);
    this.idToken = query.get(OidcConstants.QUERY_KEY_ID_TOKEN);
    this.scope = query.get(OidcConstants.QUERY_KEY_SCOPE);
    this.additionalParameters = additionalParameters;
}
exports.AuthorizationSuccessResponse = AuthorizationSuccessResponse;

AuthorizationSuccessResponse.validateResponse = function (responseUrl, request, errors) {
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

function computeExpirationDate(expiresInStr) {
    if (expiresInStr) {
        const expiresIn = +expiresInStr;
        if (isNaN(expiresIn)) {
            return null;
        } else {
            // expiresIn measures expiration from now in seconds. We send Dates to JS as milliseconds
            // since 1970, since that is what the Javascript Date constructor expects.
            return new Date(Date.now() + expiresIn * 1000).getTime();
        }
    } else {
        return null;
    }
}

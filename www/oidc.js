var exec = require('cordova/exec');

var ErrorType = {
    // The calling code did something wrong, e.g. passed an invalid authorization request,
    // such that the request couldn't even be sent to the authorization server
    UNSENDABLE_REQUEST: "OIDC_UNSENDABLE_REQUEST",
    // The authorization server returned an error response as specified in https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    ERROR_RESPONSE: "OIDC_ERROR_RESPONSE",
    // The authorization server returned an invalid response not in keeping w/ the OpenID Connect spec
    INVALID_RESPONSE: "OIDC_INVALID_RESPONSE",
    // There was an HTTP error completing the authorization request
    HTTP_ERROR: "OIDC_HTTP_ERROR",
    // The user cancelled the authorization request
    USER_CANCELLED: "OIDC_USER_CANCELLED",
    // There was an unexpected error completing the authorization request
    UNEXPECTED_ERROR: "OIDC_UNEXPECTED_ERROR"
};

module.exports = {
    ErrorType: ErrorType,
    presentAuthorizationRequest: function (req, successCb, failCb) {
        var success = function (authResponse) {
            if (successCb) successCb(new AuthorizationSuccessResponse(authResponse));
        };

        var fail = function (rawErr) {
            if (failCb) {
                var err = new Error(rawErr.type + ": " + rawErr.message);
                err.oidcType = rawErr.type;
                err.oidcDetails = rawErr.details;
                err.oidcResponse = rawErr.response ? new AuthorizationErrorResponse(rawErr.response) : null;
                failCb(err);
            }
        };

        exec(success, fail, 'OIDCBasic', 'presentAuthorizationRequest', [req]);
    },
    presentEndSessionRequest: function (req, successCb, failCb) {
        var success = function (endSessionResponse) {
            if (successCb) successCb(new EndSessionResponse(endSessionResponse));
        };

        var fail = function (rawErr) {
            if (failCb) {
                var err = new Error(rawErr.type + ": " + rawErr.message);
                err.oidcType = rawErr.type;
                err.oidcDetails = rawErr.details;
                failCb(err);
            }
        };

        exec(success, fail, 'OIDCBasic', 'presentEndSessionRequest', [req]);
    }
};

/**
 * A successful authorization response.
 */
function AuthorizationSuccessResponse(opts) {
    this.request = new AuthorizationResponseRequest(opts.request);
    this.authorizationCode = opts.authorizationCode;
    this.state = opts.state;
    this.accessToken = opts.accessToken;
    this.accesTokenExpirationDate = typeof opts.accesTokenExpirationDate === "number" ? new Date(opts.accesTokenExpirationDate) : null;
    this.tokenType = opts.tokenType;
    this.idToken = opts.idToken;
    this.scope = opts.scope;
    this.additionalParameters = opts.additionalParameters;
}

/**
 * A request returned with an authorization response. Contains info provided by calling code in
 * its presentAuthorizationRequest call plus additional request params generated by the plugin
 * (e.g. state, nonce, PKCE params).
 */
function AuthorizationResponseRequest(opts) {
    this.responseType = opts.responseType;
    this.clientId = opts.clientId;
    this.scope = opts.scope;
    this.redirectUrl = opts.redirectUrl;
    this.state = opts.state;
    this.nonce = opts.nonce;
    this.codeVerifier = opts.codeVerifier;
    this.codeChallenge = opts.codeChallenge;
    this.codeChallengeMethod = opts.codeChallengeMethod;
    this.additionalParameters = opts.additionalParameters;
}

/**
 * An error response from the authorization server as specified in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
 */
function AuthorizationErrorResponse(opts) {
    this.request = new AuthorizationResponseRequest(opts.request);
    this.error = opts.error;
    this.errorDescription = opts.errorDescription;
    this.errorUrl = opts.errorUrl;
    this.state = opts.state;
}

/**
 * A response to an end session request.
 */
function EndSessionResponse(opts) {
    this.request = new EndSessionResponseRequest(opts.request);
    this.state = opts.state;
    this.additionalParameters = opts.additionalParameters;
}

/**
 * A request returned with an end session response. Contains info provided by calling code in
 * its presentEndSessionRequest call plus additional request params generated by the plugin
 * (e.g. state).
 */
function EndSessionResponseRequest(opts) {
    this.idTokenHint = opts.idTokenHint;
    this.postLogoutRedirectUrl = opts.postLogoutRedirectUrl;
    this.state = opts.state;
    this.additionalParameters = opts.additionalParameters;
}

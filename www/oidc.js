var exec = require('cordova/exec');

var ErrorType = {
    // The authorization server returned an error response as specified in https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    PROVIDER_ERROR: "OIDC_PROVIDER_ERROR",
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
            if (successCb) successCb(authResponse);
        };

        var fail = function (rawErr) {
            if (failCb) {
                var err = new Error(rawErr.type + ": " + rawErr.message);
                err.oidcType = rawErr.type;
                err.oidcDetails = rawErr.details;
                err.oidcResponse = rawErr.response;
                failCb(err);
            }
        };

        exec(success, fail, 'OIDCBasic', 'presentAuthorizationRequest', [req]);
    }
};

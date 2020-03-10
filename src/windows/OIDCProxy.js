/**
 * Very much patterned off of AppAuth-iOS: https://github.com/openid/AppAuth-iOS
 */

var Web = Windows.Security.Authentication.Web;

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

var QUERY_KEY_ACCESS_TOKEN = "access_token";
var QUERY_KEY_CLIENT_ID = "client_id";
var QUERY_KEY_CODE = "code";
var QUERY_KEY_CODE_CHALLENGE = "code_challenge";
var QUERY_KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
var QUERY_KEY_ERROR = "error";
var QUERY_KEY_ERROR_DESCRIPTION = "error_description";
var QUERY_KEY_ERROR_URI = "error_uri";
var QUERY_KEY_EXPIRES_IN = "expires_in";
var QUERY_KEY_ID_TOKEN = "id_token";
var QUERY_KEY_NONCE = "nonce";
var QUERY_KEY_REDIRECT_URI = "redirect_uri";
var QUERY_KEY_RESPONSE_TYPE = "response_type";
var QUERY_KEY_SCOPE = "scope";
var QUERY_KEY_STATE = "state";
var QUERY_KEY_TOKEN_TYPE = "token_type";

function buildAuthorizationRequestUrl(req, callbackUri) {
    // Cf https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
    // (search "authorizationRequestURL")
    var query = new URLSearchParams();

    // Start w/ additional parameters the client has specified
    if (req.additionalParameters) {
        for (var key in req.additionalParameters) {
            query.set(key, req.additionalParameters[key]);
        }
    }

    // Next known parameters...

    // Required parameters.
    query.set(QUERY_KEY_RESPONSE_TYPE, req.responseType);
    query.set(QUERY_KEY_CLIENT_ID, req.clientId);

    // And optional parameters
    if (req.redirectUrl) {
        query.set(QUERY_KEY_REDIRECT_URI, req.redirectUrl);
    }

    if (req.scope) {
        query.set(QUERY_KEY_SCOPE, req.scope);
    }

    if (req.state) {
        query.set(QUERY_KEY_STATE, req.state);
    }

    if (req.nonce) {
        query.set(QUERY_KEY_NONCE, req.nonce);
    }

    if (req.codeChallenge) {
        query.set(QUERY_KEY_CODE_CHALLENGE, req.codeChallenge);
    }

    if (req.codeChallengeMethod) {
        query.set(QUERY_KEY_CODE_CHALLENGE_METHOD, req.codeChallengeMethod);
    }

    var url = new URL(req.configuration.authorizationEndpoint);
    url.search = query.toString();
    return url.toString();
}

function buildSuccessfulAuthorizationResponse(responseUrl) {
    // Cf https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationResponse.m
    var query = responseUrl.searchParams;
    return {
        authorizationCode: query.get(QUERY_KEY_CODE),
        state: query.get(QUERY_KEY_STATE),
        accessToken: query.get(QUERY_KEY_ACCESS_TOKEN),
        accessTokenExpirationDate: computeExpirationDate(query.get(QUERY_KEY_EXPIRES_IN)),
        tokenType: query.get(QUERY_KEY_TOKEN_TYPE),
        idToken: query.get(QUERY_KEY_ID_TOKEN),
        scope: query.get(QUERY_KEY_SCOPE),
    };
}

function computeExpirationDate(expiresIn) {
    if (typeof expiresIn === 'number') {
        // expiresIn measures expiration from now in seconds
        return new Date(Date.now() + expiresIn * 1000);
    } else {
        return expiresIn;
    }
}

function buildFailedAuthorizationResponse(responseUrl) {
    var query = responseUrl.searchParams;
    return {
        error: query.get(QUERY_KEY_ERROR),
        errorDescription: query.get(QUERY_KEY_ERROR_DESCRIPTION),
        errorUrl: query.get(QUERY_KEY_ERROR_URI),
        state: query.get(QUERY_KEY_STATE)
    };
}

function isSuccessfulAuthorizationResponse(responseUrl) {
    // Providers are required to set the error query string key in case of errors.
    // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    return !responseUrl.searchParams.get(QUERY_KEY_ERROR);
}

module.exports = {
    presentAuthorizationRequest: function (success, fail, args) {
        try {
            var req = args[0];
            // Even though we're using the authenticateAsync overload that
            // defaults the endUri to the current application's callback uri,
            // we still have to set req.redirectUrl so the redirect_uri can
            // get included in the requestUrl.
            req.redirectUrl = Web.WebAuthenticationBroker.getCurrentApplicationCallbackUri().toString();
            var requestUrl = buildAuthorizationRequestUrl(req);
            Web.WebAuthenticationBroker.authenticateAsync(Web.WebAuthenticationOptions.none, new Windows.Foundation.Uri(requestUrl)).done(function (result) {
                if (result.responseStatus === Web.WebAuthenticationStatus.success) {
                    // WebAuthenticationStatus.success only means we got a response from the auth provider.
                    // Still have to test if that was a success response or an error response.
                    // result.responseData will be the full URL that the provider redirected back to, i.e.
                    // our current application's callback uri plus the query string set by the provider.
                    var responseUrl = new URL(result.responseData);
                    if (isSuccessfulAuthorizationResponse(responseUrl)) {
                        success(buildSuccessfulAuthorizationResponse(responseUrl));
                    } else {
                        var authResp = buildFailedAuthorizationResponse(responseUrl);
                        fail({
                            type: ErrorType.PROVIDER_ERROR,
                            message: authResp.error,
                            details: authResp.errorDescription,
                            response: authResp
                        });
                    }
                } else if (result.responseStatus === Web.WebAuthenticationStatus.errorHttp) {
                    fail({
                        type: ErrorType.HTTP_ERROR,
                        message: "HTTP error, status = " + result.responseErrorDetail,
                        details: "HTTP error, status = " + result.responseErrorDetail
                    });
                } else if (result.responseStatus === Web.WebAuthenticationStatus.userCancel) {
                    fail({
                        type: ErrorType.USER_CANCELLED,
                        message: "User cancelled the authorization request.",
                        details: "User cancelled the authorization request."
                    });
                } else {
                    fail({
                        type: ErrorType.UNEXPECTED_ERROR,
                        message: "Unexpected response status `" + result.responseStatus + "`",
                        details: "Unexpected response status `" + result.responseStatus + "`",
                    });
                }
            });
        } catch (e) {
            fail({
                type: ErrorType.UNEXPECTED_ERROR,
                message: e.message,
                details: e.stack
            });
        }
    }
};

require("cordova/exec/proxy").add("OIDCBasic", module.exports);

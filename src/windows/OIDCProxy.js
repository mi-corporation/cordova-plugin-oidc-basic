/**
 * Very much patterned off of AppAuth-iOS: https://github.com/openid/AppAuth-iOS
 */

 /* global Windows, OIDCBasicRuntimeComponent */

var Web = Windows.Security.Authentication.Web;
var RtComponent = OIDCBasicRuntimeComponent;

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

var QUERY_KEY_ACCESS_TOKEN = "access_token";
var QUERY_KEY_CODE = "code";
var QUERY_KEY_ERROR = "error";
var QUERY_KEY_ERROR_DESCRIPTION = "error_description";
var QUERY_KEY_ERROR_URI = "error_uri";
var QUERY_KEY_EXPIRES_IN = "expires_in";
var QUERY_KEY_ID_TOKEN = "id_token";
var QUERY_KEY_SCOPE = "scope";
var QUERY_KEY_STATE = "state";
var QUERY_KEY_TOKEN_TYPE = "token_type";

function validateAuthorizationRequestParams(reqParams, errors) {
    if (!reqParams) {
        errors.push("request params object is required");
    } else {
        if (!reqParams.configuration) {
            errors.push("configuration param is required");
        } else {
            if (reqParams.configuration.authorizationEndpoint === null || reqParams.configuration.authorizationEndpoint === undefined) {
                errors.push("configuration.authorizationEndpoint param is required");
            } else if (typeof reqParams.configuration.authorizationEndpoint !== "string") {
                errors.push("configuration.authorizationEndpoint param must be a string");
            } else if (!isValidURL(reqParams.configuration.authorizationEndpoint)) {
                errors.push("configuration.authorizationEndpoint param must be a valid URL");
            }
        }
        if (reqParams.responseType === null || reqParams.responseType === undefined) {
            errors.push("responseType param is required");
        } else if (typeof reqParams.responseType !== "string") {
            errors.push("responseType param must be a string");
        }
        if (reqParams.clientID === null || reqParams.clientID === undefined) {
            errors.push("clientID param is required");
        } else if (typeof reqParams.clientID !== "string") {
            errors.push("clientID param must be a string");
        }
        if (reqParams.scope !== null && reqParams.scope !== undefined && typeof reqParams.scope !== "string") {
            errors.push("scope param must be a string");
        }
        if (reqParams.redirectURL !== null && reqParams.redirectURL !== undefined) {
            if (typeof reqParams.redirectURL !== "string") {
                errors.push("redirectURL must be a string");
            } else if (!isValidURL(reqParams.redirectURL)) {
                errors.push("redirectURL must be a valid URL");
            }
        }
        if (reqParams.state !== null && reqParams.state !== undefined && typeof reqParams.state !== "string") {
            errors.push("state param must be a string");
        }
    }
    return errors.length === 0;
}

function isValidURL(url) {
    try {
        new Windows.Foundation.Uri(url);
        return true;
    } catch (e) {
        return false;
    }
}

function buildAuthorizationRequestParamsForJSParams(jsReqParams) {
    var configuration = new RtComponent.AuthorizationServiceConfiguration();
    configuration.authorizationEndpoint = new Windows.Foundation.Uri(jsReqParams.configuration.authorizationEndpoint);
    var requestParams = new RtComponent.AuthorizationRequestParams();
    requestParams.configuration = configuration;
    requestParams.clientID = jsReqParams.clientID;
    requestParams.scope = jsReqParams.scope;
    requestParams.redirectURL = jsReqParams.redirectURL ? new Windows.Foundation.Uri(jsReqParams.redirectURL) : null;
    requestParams.responseType = jsReqParams.responseType;
    requestParams.state = jsReqParams.state;
    requestParams.additionalParameters = buildPropertySetForJSObj(jsReqParams.additionalParameters);
    return requestParams;
}

function buildSuccessfulAuthorizationResponse(responseUrl, request) {
    // Cf https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationResponse.m
    var query = responseUrl.searchParams;
    var expectedQueryKeys = [
        QUERY_KEY_CODE,
        QUERY_KEY_STATE,
        QUERY_KEY_EXPIRES_IN,
        QUERY_KEY_TOKEN_TYPE,
        QUERY_KEY_ID_TOKEN,
        QUERY_KEY_SCOPE
    ];
    var additionalParameters = {};
    query.forEach(function (value, key) {
        if (expectedQueryKeys.indexOf(key) < 0) additionalParameters[key] = value;
    });
    return {
        request: request,
        authorizationCode: query.get(QUERY_KEY_CODE),
        state: query.get(QUERY_KEY_STATE),
        accessToken: query.get(QUERY_KEY_ACCESS_TOKEN),
        accessTokenExpirationDate: computeExpirationDate(query.get(QUERY_KEY_EXPIRES_IN)),
        tokenType: query.get(QUERY_KEY_TOKEN_TYPE),
        idToken: query.get(QUERY_KEY_ID_TOKEN),
        scope: query.get(QUERY_KEY_SCOPE),
        additionalParameters: additionalParameters
    };
}

function computeExpirationDate(expiresIn) {
    if (typeof expiresIn === 'number') {
        // expiresIn measures expiration from now in seconds. We send Dates to JS as milliseconds
        // since 1970, since that is what the Javascript Date constructor expects.
        return new Date(Date.now() + expiresIn * 1000).getTime();
    } else {
        return expiresIn;
    }
}

function buildFailedAuthorizationResponse(responseUrl, request) {
    var query = responseUrl.searchParams;
    return {
        request: request,
        error: query.get(QUERY_KEY_ERROR),
        errorDescription: query.get(QUERY_KEY_ERROR_DESCRIPTION),
        errorURL: query.get(QUERY_KEY_ERROR_URI),
        state: query.get(QUERY_KEY_STATE)
    };
}

function isAuthorizationErrorResponse(responseUrl) {
    // Providers are required to set the error query string key in case of errors.
    // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    return !!responseUrl.searchParams.get(QUERY_KEY_ERROR);
}

function validateAuthorizationNonErrorResponse(responseUrl, request, errors) {
    var query = responseUrl.searchParams;

    // Validate that returned state matches the value from the request, for parity with
    // AppAuth-iOS.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationService.m
    // (search "OIDErrorCodeOAuthAuthorizationClientError").
    var responseState = query.get(QUERY_KEY_STATE);
    if (request.state !== responseState) {
        errors.push("State mismatch, expecting " + request.state + " but got " + responseState);
    }

    return errors.length === 0;
}

function buildPropertySetForJSObj(obj) {
    if (obj) {
        var propSet = new Windows.Foundation.PropertySet();
        for (var key in obj) {
            propSet.insert(key, obj[key]);
        }
        return propSet;
    } else {
        return null;
    }
}

function requestValidationErrorsResponse(errors) {
    var message = "Request contained the following validation errors: " + errors.join(", ");
    return {
        type: ErrorType.UNSENDABLE_REQUEST,
        message: message,
        details: message
    };
}

function responseValidationErrorsResponse(errors) {
    var message = "Invalid response: " + errors.join(", ");
    return {
        type: ErrorType.INVALID_RESPONSE,
        message: message,
        details: message
    };
}

module.exports = {
    presentAuthorizationRequest: function (success, fail, args) {
        try {
            var reqParams = args[0];

            var errors = [];
            if (!validateAuthorizationRequestParams(reqParams, errors)) {
                fail(requestValidationErrorsResponse(errors));
                return;
            }

            var requestParams = buildAuthorizationRequestParamsForJSParams(reqParams);
            var request;
            // generateRequestAsync calls into IdentityModel.OidcClient to generate the request,
            // including things like nonce, state, and PKCE params. We'll then handle calling
            // WebAuthenticationBroker.authenticateAsync and processing its response ourselves.
            // IdentityModel.OidcClient doesn't actually ship any code to display the authorization
            // request to the end user (calling code implements its IBrowser interface for that).
            // And if you do implement IBrowser, IdentityModel.OidcClient's LoginAsync method
            // assumes you wanna do the token exchange on device, which is not the goal of this
            // plugin.
            // See https://github.com/IdentityModel/IdentityModel.OidcClient/blob/master/src/OidcClient.cs
            // and https://github.com/IdentityModel/IdentityModel.OidcClient/blob/master/src/Browser/IBrowser.cs
            requestParams.generateRequestAsync().then(function (_request) {
                request = _request;
                return Web.WebAuthenticationBroker.authenticateAsync(Web.WebAuthenticationOptions.none, request.requestURL, request.redirectURL);
            }).done(function (result) {
                if (result.responseStatus === Web.WebAuthenticationStatus.success) {
                    // WebAuthenticationStatus.success only means we got a response from the auth provider.
                    // Still have to test if that was a success response or an error response.
                    // result.responseData will be the full URL that the provider redirected back to, i.e.
                    // our current application's callback uri plus the query string set by the provider.
                    var responseUrl = new URL(result.responseData);
                    if (isAuthorizationErrorResponse(responseUrl)) {
                        var authResp = buildFailedAuthorizationResponse(responseUrl, request);
                        fail({
                            type: ErrorType.ERROR_RESPONSE,
                            message: authResp.error,
                            details: authResp.errorDescription,
                            response: authResp
                        });
                    } else {
                        var errors2 = [];
                        if (validateAuthorizationNonErrorResponse(responseUrl, request, errors2)) {
                            success(buildSuccessfulAuthorizationResponse(responseUrl, request));
                        } else {
                            fail(responseValidationErrorsResponse(errors2));
                        }
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

/**
 * Very much patterned off of AppAuth-iOS: https://github.com/openid/AppAuth-iOS
 */

 /* global Windows */

var Web = Windows.Security.Authentication.Web;

var AuthorizationErrorResponse = require("./authorizationErrorResponse").AuthorizationErrorResponse;
var AuthorizationRequest = require("./authorizationRequest").AuthorizationRequest;
var AuthorizationSuccessResponse = require("./authorizationSuccessResponse").AuthorizationSuccessResponse;
var EndSessionRequest = require("./endSessionRequest").EndSessionRequest;
var EndSessionResponse = require("./endSessionResponse").EndSessionResponse;

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

function requestValidationErrorsResponse(errors) {
    var message = "Request contained the following validation errors: " + errors.join(", ");
    return {
        type: ErrorType.UNSENDABLE_REQUEST,
        message: message,
        details: message
    };
}

function authorizationFlowAlreadyInProgressResponse() {
    var message = "Cannot send this request b/c another authorization flow is already in progress.";
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

function webAuthenticationBrokerErrorResponse(result) {
    if (result.responseStatus === Web.WebAuthenticationStatus.errorHttp) {
        return {
            type: ErrorType.HTTP_ERROR,
            message: "HTTP error, status = " + result.responseErrorDetail,
            details: "HTTP error, status = " + result.responseErrorDetail
        };
    } else if (result.responseStatus === Web.WebAuthenticationStatus.userCancel) {
        return {
            type: ErrorType.USER_CANCELLED,
            message: "User cancelled the request.",
            details: "User cancelled the request."
        };
    } else {
        return {
            type: ErrorType.UNEXPECTED_ERROR,
            message: "Unexpected response status `" + result.responseStatus + "`",
            details: "Unexpected response status `" + result.responseStatus + "`",
        };
    }
}

function unexpectedErrorResponse(e) {
    return {
        type: ErrorType.UNEXPECTED_ERROR,
        message: e.message,
        details: e.stack
    };
}

function unexpectedWebAuthBrokerRejectionResponse(e) {
    return {
        type: ErrorType.UNEXPECTED_ERROR,
        message: typeof e.message === "string" ? e.message.trim("\n") : "",
        details: [
            e.toString().trim("\n"),
            e.asyncOpSource && typeof e.asyncOpSource.stack === "string" ? e.asyncOpSource.stack.trim("\n") : ""
        ].join("\n")
    };
}

var authorizationFlowInProgress = false;

module.exports = {
    presentAuthorizationRequest: function (success, fail, args) {
        try {
            var reqParams = args[0];

            var errors = [];
            if (!AuthorizationRequest.validateParams(reqParams, errors)) {
                fail(requestValidationErrorsResponse(errors));
                return;
            }

            var request = new AuthorizationRequest(reqParams);
            var requestUrl = new Windows.Foundation.Uri(request.buildRequestUrl());
            var redirectUrl = request.redirectUrl === null ? null : new Windows.Foundation.Uri(request.redirectUrl);

            if (authorizationFlowInProgress) {
                fail(authorizationFlowAlreadyInProgressResponse());
                return;
            }

            authorizationFlowInProgress = true;

            Web.WebAuthenticationBroker.authenticateAsync(Web.WebAuthenticationOptions.none, requestUrl, redirectUrl).done(function (result) {
                authorizationFlowInProgress = false;
                try {
                    if (result.responseStatus === Web.WebAuthenticationStatus.success) {
                        // WebAuthenticationStatus.success only means we got a response from the auth provider.
                        // Still have to test if that was a success response or an error response.
                        // result.responseData will be the full URL that the provider redirected back to, i.e.
                        // our current application's callback uri plus the query string set by the provider.
                        var responseUrl = new URL(result.responseData);
                        if (AuthorizationErrorResponse.isErrorResponse(responseUrl)) {
                            errors = [];
                            if (AuthorizationErrorResponse.validateResponse(responseUrl, request, errors)) {
                                var authResp = new AuthorizationErrorResponse(responseUrl, request);
                                fail({
                                    type: ErrorType.ERROR_RESPONSE,
                                    message: authResp.error,
                                    details: authResp.errorDescription,
                                    response: authResp
                                });
                            } else {
                                fail(responseValidationErrorsResponse(errors));
                            }
                        } else {
                            errors = [];
                            if (AuthorizationSuccessResponse.validateResponse(responseUrl, request, errors)) {
                                success(new AuthorizationSuccessResponse(responseUrl, request));
                            } else {
                                fail(responseValidationErrorsResponse(errors));
                            }
                        }
                    } else {
                        fail(webAuthenticationBrokerErrorResponse(result));
                    }
                } catch (e) {
                    fail(unexpectedErrorResponse(e));
                }
            }, function (e) {
                authorizationFlowInProgress = false;
                fail(unexpectedWebAuthBrokerRejectionResponse(e));
            });
        } catch (e) {
            authorizationFlowInProgress = false;
            fail(unexpectedErrorResponse(e));
        }
    },
    presentEndSessionRequest: function (success, fail, args) {
        try {
            var reqParams = args[0];

            var errors = [];
            if (!EndSessionRequest.validateParams(reqParams, errors)) {
                fail(requestValidationErrorsResponse(errors));
                return;
            }

            var request = new EndSessionRequest(reqParams);
            var requestUrl = new Windows.Foundation.Uri(request.buildRequestUrl());
            var redirectUrl = request.postLogoutRedirectUrl === null ? null : new Windows.Foundation.Uri(request.postLogoutRedirectUrl);

            if (authorizationFlowInProgress) {
                fail(authorizationFlowAlreadyInProgressResponse());
                return;
            }

            authorizationFlowInProgress = true;

            Web.WebAuthenticationBroker.authenticateAsync(Web.WebAuthenticationOptions.none, requestUrl, redirectUrl).done(function (result) {
                authorizationFlowInProgress = false;
                try {
                    if (result.responseStatus === Web.WebAuthenticationStatus.success) {
                        var responseUrl = new URL(result.responseData);
                        var errors2 = [];
                        if (EndSessionResponse.validateResponse(responseUrl, request, errors2)) {
                            success(new EndSessionResponse(responseUrl, request));
                        } else {
                            fail(responseValidationErrorsResponse(errors2));
                        }
                    } else {
                        fail(webAuthenticationBrokerErrorResponse(result));
                    }
                } catch (e) {
                    fail(unexpectedErrorResponse(e));
                }
            }, function (e) {
                authorizationFlowInProgress = false;
                fail(unexpectedWebAuthBrokerRejectionResponse(e));
            });
        } catch (e) {
            authorizationFlowInProgress = false;
            fail(unexpectedErrorResponse(e));
        }
    }
};

require("cordova/exec/proxy").add("OIDCBasic", module.exports);

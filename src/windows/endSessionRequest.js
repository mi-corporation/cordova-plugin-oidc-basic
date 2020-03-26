var OidcConstants = require("./oidcConstants");
var CryptoUtils = require("./cryptoUtils");
var isValidUrl = require("./isValidUrl").isValidUrl;

function EndSessionRequest(reqParams) {
    this.configuration = reqParams.configuration;
    this.idTokenHint = reqParams.idTokenHint === undefined ? null : reqParams.idTokenHint;
    this.postLogoutRedirectUrl = reqParams.postLogoutRedirectUrl === undefined ? null : reqParams.postLogoutRedirectUrl;
    this.state = reqParams.state === null || reqParams.state === undefined ? CryptoUtils.createRandomId(32) : reqParams.state;
    this.additionalParameters = sanitizeAdditionalParams(reqParams.additionalParameters);
}
exports.EndSessionRequest = EndSessionRequest;

EndSessionRequest.validateParams = function (reqParams, errors) {
    var initLength = errors.length;

    if (!reqParams) {
        errors.push("request params object is required");
    } else {
        if (!reqParams.configuration) {
            errors.push("configuration param is required");
        } else {
            if (reqParams.configuration.endSessionEndpoint === null || reqParams.configuration.endSessionEndpoint === undefined) {
                errors.push("configuration.endSessionEndpoint param is required");
            } else if (typeof reqParams.configuration.endSessionEndpoint !== "string") {
                errors.push("configuration.endSessionEndpoint param must be a string");
            } else if (!isValidUrl(reqParams.configuration.endSessionEndpoint)) {
                errors.push("configuration.endSessionEndpoint param must be a valid URL");
            }
        }
        if (reqParams.postLogoutRedirectUrl !== null && reqParams.postLogoutRedirectUrl !== undefined) {
            if (typeof reqParams.postLogoutRedirectUrl !== "string") {
                errors.push("postLogoutRedirectUrl param must be a string");
            } else if (!isValidUrl(reqParams.postLogoutRedirectUrl)) {
                errors.push("postLogoutRedirectUrl param must be a valid URL");
            }
        }
        if (reqParams.idTokenHint !== null && reqParams.idTokenHint !== undefined && typeof reqParams.idTokenHint !== "string") {
            errors.push("idTokenHint param must be a string");
        }
        if (reqParams.state !== null && reqParams.state !== undefined && typeof reqParams.state !== "string") {
            errors.push("state param must be a string");
        }
    }

    return errors.length === initLength;
};

EndSessionRequest.prototype.buildRequestUrl = function () {
    var query = new URLSearchParams();

    if (this.postLogoutRedirectUrl) {
        query.set(OidcConstants.QUERY_KEY_POST_LOGOUT_REDIRECT_URI, this.postLogoutRedirectUrl);
    }
    if (this.idTokenHint) {
        query.set(OidcConstants.QUERY_KEY_ID_TOKEN_HINT, this.idTokenHint);
    }
    if (this.state) {
        query.set(OidcConstants.QUERY_KEY_STATE, this.state);
    }

    if (this.additionalParameters) {
        for (var key in this.additionalParameters) {
            query.set(key, this.additionalParameters[key]);
        }
    }

    var url = new URL(this.configuration.endSessionEndpoint);
    url.search = query.toString();
    return url.toString();
};

var BLACKLISTED_PARAMS = [
    OidcConstants.QUERY_KEY_ID_TOKEN_HINT,
    OidcConstants.QUERY_KEY_POST_LOGOUT_REDIRECT_URI,
    OidcConstants.QUERY_KEY_STATE
];

function sanitizeAdditionalParams(additionalParameters) {
    if (additionalParameters) {
        var sanitized = {};
        for (var key in additionalParameters) {
            if (BLACKLISTED_PARAMS.indexOf(key) < 0) sanitized[key] = additionalParameters[key];
        }
        return sanitized;
    } else {
        return null;
    }
}

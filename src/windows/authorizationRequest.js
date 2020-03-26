var OidcConstants = require("./oidcConstants");
var CryptoUtils = require("./cryptoUtils");
var isValidUrl = require("./isValidUrl").isValidUrl;

function AuthorizationRequest(reqParams) {
    this.configuration = reqParams.configuration;
    this.responseType = reqParams.responseType === undefined ? null : reqParams.responseType;
    this.clientId = reqParams.clientId === undefined ? null : reqParams.clientId;
    this.scope = reqParams.scope === undefined ? null : reqParams.scope;
    this.redirectUrl = reqParams.redirectUrl === undefined ? null : reqParams.redirectUrl;
    // If calling code passed in state, use it, otherwise generate random state.
    // This is needed to support the use case of calling code encoding current UI state or other info in the state
    // param. But it also means calling code has the responsibility for using the state param correctly. In particular,
    // the spec says that clients SHOULD make their state param opaque and non-guessable.
    // See https://tools.ietf.org/html/rfc6749#section-10.12.
    // (For what it's worth, I think that section applies more closely to web apps and that for native apps PKCE
    // defends against the same attacks in a more robust way. But I'd still recommend calling code make their state
    // opaque and non-guessable as an extra security measure.)
    // NOTE: If we DO generate random state, we closely follow the method used by AppAuth-iOS.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
    this.state = reqParams.state === null || reqParams.state === undefined ? CryptoUtils.createRandomId(32) : reqParams.state;
    // NOTE: nonce generation closely follows the method used by AppAuth-iOS.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
    this.nonce = CryptoUtils.createRandomId(32);
    // NOTE: codeVerifier generation closely follows the method used by AppAuth-iOS.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
    this.codeVerifier = CryptoUtils.createRandomId(32);
    this.codeChallenge = CryptoUtils.computeS256CodeChallenge(this.codeVerifier);
    this.codeChallengeMethod = OidcConstants.CODE_CHALLENGE_METHOD_S256;
    this.additionalParameters = sanitizeAdditionalParams(reqParams.additionalParameters);
}
exports.AuthorizationRequest = AuthorizationRequest;

AuthorizationRequest.validateParams = function (reqParams, errors) {
    var initLength = errors.length;

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
            } else if (!isValidUrl(reqParams.configuration.authorizationEndpoint)) {
                errors.push("configuration.authorizationEndpoint param must be a valid URL");
            }
        }
        if (reqParams.responseType === null || reqParams.responseType === undefined) {
            errors.push("responseType param is required");
        } else if (typeof reqParams.responseType !== "string") {
            errors.push("responseType param must be a string");
        }
        if (reqParams.clientId === null || reqParams.clientId === undefined) {
            errors.push("clientId param is required");
        } else if (typeof reqParams.clientId !== "string") {
            errors.push("clientId param must be a string");
        }
        if (reqParams.scope !== null && reqParams.scope !== undefined && typeof reqParams.scope !== "string") {
            errors.push("scope param must be a string");
        }
        if (reqParams.redirectUrl !== null && reqParams.redirectUrl !== undefined) {
            if (typeof reqParams.redirectUrl !== "string") {
                errors.push("redirectUrl param must be a string");
            } else if (!isValidUrl(reqParams.redirectUrl)) {
                errors.push("redirectUrl param must be a valid URL");
            }
        }
        if (reqParams.state !== null && reqParams.state !== undefined && typeof reqParams.state !== "string") {
            errors.push("state param must be a string");
        }
    }

    return errors.length === initLength;
};

AuthorizationRequest.prototype.buildRequestUrl = function () {
    // Cf https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
    // (search "authorizationRequestURL")
    var query = new URLSearchParams();

    query.set(OidcConstants.QUERY_KEY_RESPONSE_TYPE, this.responseType);
    query.set(OidcConstants.QUERY_KEY_CLIENT_ID, this.clientId);
    if (this.redirectUrl) {
        query.set(OidcConstants.QUERY_KEY_REDIRECT_URI, this.redirectUrl);
    }
    if (this.scope) {
        query.set(OidcConstants.QUERY_KEY_SCOPE, this.scope);
    }
    if (this.state) {
        query.set(OidcConstants.QUERY_KEY_STATE, this.state);
    }
    if (this.nonce) {
        query.set(OidcConstants.QUERY_KEY_NONCE, this.nonce);
    }
    if (this.codeChallenge) {
        query.set(OidcConstants.QUERY_KEY_CODE_CHALLENGE, this.codeChallenge);
    }
    if (this.codeChallengeMethod) {
        query.set(OidcConstants.QUERY_KEY_CODE_CHALLENGE_METHOD, this.codeChallengeMethod);
    }

    if (this.additionalParameters) {
        for (var key in this.additionalParameters) {
            query.set(key, this.additionalParameters[key]);
        }
    }

    var url = new URL(this.configuration.authorizationEndpoint);
    url.search = query.toString();
    return url.toString();
};

var BLACKLISTED_PARAMS = [
    OidcConstants.QUERY_KEY_SCOPE,
    OidcConstants.QUERY_KEY_RESPONSE_TYPE,
    OidcConstants.QUERY_KEY_CLIENT_ID,
    OidcConstants.QUERY_KEY_REDIRECT_URI,
    OidcConstants.QUERY_KEY_STATE,
    OidcConstants.QUERY_KEY_NONCE,
    OidcConstants.QUERY_KEY_CODE_CHALLENGE,
    OidcConstants.QUERY_KEY_CODE_CHALLENGE_METHOD
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

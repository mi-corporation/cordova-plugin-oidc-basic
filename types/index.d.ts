interface CordovaPluginOIDCBasic {
    ErrorType: OIDCBasicErrorTypeLookup;
    /**
     * Present the end user with an authorization request. This is the main entrypoint to any
     * OpenID Connect/OAuth 2.0 flow.
     */
    presentAuthorizationRequest(req: OIDCBasicAuthorizationRequestOptions, successCb?: (resp: OIDCBasicAuthorizationSuccessResponse) => void, errorCb?: (err: OIDCBasicError) => void): void;
    /**
     * Present the end user with an end session request.
     */
    presentEndSessionRequest(req: OIDCBasicEndSessionRequestOptions, successCb?: (resp: OIDCBasicEndSessionResponse) => void, errorCb?: (err: OIDCBasicError) => void): void;
}

/**
 * Options to initiate an authorization request.
 * See https://openid.net/specs/openid-connect-core-1_0.html#Authentication
 * and https://tools.ietf.org/html/rfc6749#section-4
 */
interface OIDCBasicAuthorizationRequestOptions {
    /**
     * Configuration for the service accepting the request.
     */
    configuration: OIDCBasicAuthorizationServiceConfiguration;
    /**
     * The OpenID Connect/OAuth 2.0 response_type.
     * See https://openid.net/specs/openid-connect-core-1_0.html#Authentication
     * and https://tools.ietf.org/html/rfc6749#section-3.1.1
     */
    responseType: string;
    /**
     * The OpenID Connect/OAuth 2.0 client_id.
     * See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     * and https://tools.ietf.org/html/rfc6749#section-2.2
     * and https://tools.ietf.org/html/rfc6749#section-4.1.1
     */
    clientId: string;
    /**
     * The OpenID Connect/OAuth 2.0 scope. This is a space delimited string. For OpenID
     * Connect, one of the space delimited tokens MUST be "openid".
     * See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     * and https://tools.ietf.org/html/rfc6749#section-3.3
     * and https://tools.ietf.org/html/rfc6749#section-4.1.1
     */
    scope?: string | null;
    /**
     * The OpenID Connect/OAuth 2.0 redirect_uri.
     * See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     * and https://tools.ietf.org/html/rfc6749#section-3.1.2
     * and https://tools.ietf.org/html/rfc6749#section-4.1.1
     */
    redirectUrl?: string | null;
    /**
     * The OpenID Connect/OAuth 2.0 state. If left null or undefined, cordova-plugin-oidc-basic
     * will generate a random state value. If providing your own state value, it is strongly
     * recommended that you make the value non-guessable, e.g. by generating part of the
     * value randomly as described by https://tools.ietf.org/html/rfc6749#section-10.12.
     * See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     * and https://tools.ietf.org/html/rfc6749#section-10.12
     * and https://tools.ietf.org/html/rfc6749#section-4.1.1
     */
    state?: string | null;
    /**
     * An object whose keys are additional keys to include in the authorization request's query
     * string (must match the desired query string key exactly) and whose values are the string
     * values for those keys.
     */
    additionalParameters?: OIDCBasicAdditionalParameters | null;
}

/**
 * Options to initiate an end session request.
 * See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
 */
interface OIDCBasicEndSessionRequestOptions {
    /**
     * Configuration for the service accepting the request.
     */
    configuration: OIDCBasicEndSessionServiceConfiguration;
    /**
     * The id_token_hint value. See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
     */
    idTokenHint?: string | null;
    /**
     * The post_logout_redirect_uri value. See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
     */
    postLogoutRedirectUrl?: string | null;
    /**
     * The OpenID Connect/OAuth 2.0 state. If left null or undefined, cordova-plugin-oidc-basic
     * will generate a random state value.
     * See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
     */
    state?: string | null;
    /**
     * An object whose keys are additional keys to include in the end session request's query
     * string (must match the desired query string key exactly) and whose values are the string
     * values for those keys.
     */
    additionalParameters?: OIDCBasicAdditionalParameters | null;
}

/**
 * Configuration for a service than can accept authorization requests.
 */
interface OIDCBasicAuthorizationServiceConfiguration {
    /**
     * The authorization endpoint.
     */
    authorizationEndpoint: string;
}

/**
 * Configuration for a service that can accept end session requests.
 */
interface OIDCBasicEndSessionServiceConfiguration {
    /**
     * The end session endpoint.
     */
    endSessionEndpoint: string;
}

/**
 * Configuration for a service that can accept all request types of interest to cordova-plugin-oidc-basic.
 */
interface OIDCBasicServiceConfiguration extends OIDCBasicAuthorizationServiceConfiguration, OIDCBasicEndSessionServiceConfiguration {}

/**
 * A successful authorization response.
 * See https://openid.net/specs/openid-connect-core-1_0.html#Authentication
 * and https://tools.ietf.org/html/rfc6749#section-4
 */
interface OIDCBasicAuthorizationSuccessResponse {
    /**
     * The request for which this response was returned.
     */
    request: OIDCBasicAuthorizationResponseRequest;
    /**
     * The OpenID Connect/OAuth 2.0 authorization code obtained as part of the authorization
     * code flow.
     * See https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     * and https://tools.ietf.org/html/rfc6749#section-4.1
     */
    authorizationCode: string | null;
    /**
     * The state value echoed back by the authorization server. cordova-plugin-oidc-basic
     * ensures that this matches the request's state value exactly, otherwise it calls the
     * provided error callback with an error of type
     * `cordova.plugins.oidc.basic.ErrorType.INVALID_RESPONSE`.
     */
    state: string | null;
    /**
     * The OpenID Connect/OAuth 2.0 access token obtained as part of the implicit flow.
     * See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     * and https://tools.ietf.org/html/rfc6749#section-4.2
     */
    accessToken: string | null;
    /**
     * The access token expiration date computed from the response's expires_in value as part
     * of the implicit flow.
     * See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
     * and https://tools.ietf.org/html/rfc6749#section-4.2.2
     */
    accessTokenExpirationDate: Date | null;
    /**
     * The OpenID Connect/OAuth 2.0 token_type obtained as part of the implicit flow.
     * See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
     * and https://tools.ietf.org/html/rfc6749#section-4.2.2
     * and https://tools.ietf.org/html/rfc6749#section-7.1
     */
    tokenType: string | null;
    /**
     * The OpenID Connect id_token obtained as part of the implicit flow.
     * See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
     */
    idToken: string | null;
    /**
     * The OAuth 2.0 scope optionally included with implicit flow responses.
     * See https://tools.ietf.org/html/rfc6749#section-4.2.2
     */
    scope: string | null;
    /**
     * An object whose keys are additional keys included with the authorization response's
     * query string and whose values are the string values for those keys.
     */
    additionalParameters: OIDCBasicAdditionalParameters | null;
}

/**
 * A request returned with an authorization response. Contains info provided by calling code in
 * its presentAuthorizationRequest call plus additional request params generated by the plugin
 * (e.g. state, nonce, PKCE params).
 */
interface OIDCBasicAuthorizationResponseRequest {
    /**
     * The `responseType` provided in the `presentAuthorizationRequest` call.
     */
    responseType: string;
    /**
     * The `clientId` provided in the `presentAuthorizationRequest` call.
     */
    clientId: string;
    /**
     * The `scope` provided in the `presentAuthorizationRequest` call.
     */
    scope: string | null;
    /**
     * The `redirectUrl` provided in the `presentAuthorizationRequest` call.
     */
    redirectUrl: string | null;
    /**
     * The `state` provided in the `presentAuthorizationRequest` call, if not null or
     * undefined, otherwise the state value randomly generated by cordova-plugin-oidc-basic.
     */
    state: string | null;
    /**
     * The nonce value randomly generated by cordova-plugin-oidc-basic.
     * There is currently no option to disable nonce generation.
     * See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
     */
    nonce: string | null;
    /**
     * The code_verifier value randomly generated by cordova-plugin-oidc-basic. This is a
     * component of PKCE. For authorization servers that enforce PKCE validation, you must
     * provide this value to the token endpoint as part of token exchange. There is currently
     * no option to disable generation of PKCE parameters.
     * See https://tools.ietf.org/html/rfc7636#section-4.5
     */
    codeVerifier: string | null;
    /**
     * The code_challenge value generated by cordova-plugin-oidc-basic. This is a component
     * of PKCE. It is included here for completeness only.
     * See https://tools.ietf.org/html/rfc7636#section-4.2
     */
    codeChallenge: string | null;
    /**
     * The code_challenge_method used by cordova-plugin-oidc-basic. This is a component of
     * PKCE. It is included here for completeness only.
     * See https://tools.ietf.org/html/rfc7636#section-4.2
     */
    codeChallengeMethod: "S256" | null;
    /**
     * An object whose keys are additional keys that were included in the authorization
     * request's query string and whose values are the string values for those keys.
     */
    additionalParameters: OIDCBasicAdditionalParameters | null;
}

/**
 * An error response from the authorization server as specified in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
 */
interface OIDCBasicAuthorizationErrorResponse {
    /**
     * The request for which this response was returned.
     */
    request: OIDCBasicAuthorizationResponseRequest;
    /**
     * The error value. See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
     */
    error: string;
    /**
     * The error_description value. See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
     */
    errorDescription: string | null;
    /**
     * The error_uri value. See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
     */
    errorUrl: string | null;
    /**
     * The state value echoed back by the authorization server. cordova-plugin-oidc-basic
     * ensures that this matches the request's state value exactly, otherwise it calls the
     * provided error callback with an error of type
     * `cordova.plugins.oidc.basic.ErrorType.INVALID_RESPONSE`.
     */
    state: string | null;
}

/**
 * A response to an end session request.
 * See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
 */
interface OIDCBasicEndSessionResponse {
    /**
     * The request for which this response was returned.
     */
    request: OIDCBasicEndSessionResponseRequest;
    /**
     * The state value echoed back by the end session endpoint. cordova-plugin-oidc-basic
     * ensures that this matches the request's state value exactly, otherwise it calls the
     * provided error callback with an error of type
     * `cordova.plugins.oidc.basic.ErrorType.INVALID_RESPONSE`.
     */
    state: string | null;
    /**
     * An object whose keys are additional keys included with the end session response's
     * query string and whose values are the string values for those keys.
     */
    additionalParameters: OIDCBasicAdditionalParameters | null;
}

/**
 * A request returned with an end session response. Contains info provided by calling code in
 * its presentEndSessionRequest call plus additional request params generated by the plugin
 * (e.g. state).
 */
interface OIDCBasicEndSessionResponseRequest {
    /**
     * The `idTokenHint` provided in the `presentEndSessionRequest` call.
     */
    idTokenHint: string | null;
    /**
     * The `postLogoutRedirectUrl` provided in the `presentEndSessionRequest` call.
     */
    postLogoutRedirectUrl: string | null;
    /**
     * The `state` provided in the `presentEndSessionRequest` call, if not null or undefined,
     * otherwise the state value randomly generated by cordova-plugin-oidc-basic.
     */
    state: string | null;
    /**
     * An object whose keys are additional keys that were included in the end session
     * request's query string and whose values are the string values for those keys.
     */
    additionalParameters: OIDCBasicAdditionalParameters | null;
}

type OIDCBasicAdditionalParameters = { [key: string]: string | undefined; }

/**
 * A dictionary of known error types. cordova-plugin-oidc-basic may add other error types in
 * the future. Do NOT assume that this list is exhaustive.
 */
interface OIDCBasicErrorTypeLookup {
    UNSENDABLE_REQUEST: "OIDC_UNSENDABLE_REQUEST";
    ERROR_RESPONSE: "OIDC_ERROR_RESPONSE";
    INVALID_RESPONSE: "OIDC_INVALID_RESPONSE";
    HTTP_ERROR: "OIDC_HTTP_ERROR";
    USER_CANCELLED: "OIDC_USER_CANCELLED";
    UNEXPECTED_ERROR: "OIDC_UNEXPECTED_ERROR";
}

/**
 * A standard JS error augemented with extra fields by cordova-plugin-oidc-basic.
 */
interface OIDCBasicError extends Error {
    /**
     * A type discriminator. Use like
     * ```
     * if (e.oidcType === cordova.plugins.oidc.basic.ErrorType.ERROR_RESPONSE) {
     *     // The authorization server returned an error response
     * }
     * ```
     */
    oidcType: string;
    /**
     * Additional details about the error.
     */
    oidcDetails: string | null;
    /**
     * If `oidcType` is `cordova.plugins.oidc.basic.ErrorType.ERROR_RESPONSE`, then this will
     * be populated with the error response.
     */
    oidcResponse?: OIDCBasicAuthorizationErrorResponse | null;
}

interface CordovaPlugins {
    oidc: { basic: CordovaPluginOIDCBasic };
}

package com.mico.cordova.plugin.oidc.basic;

import static android.util.Log.getStackTraceString;

import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Patterns;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class OIDCBasic extends CordovaPlugin {
    private static final String LOG_TAG = "OIDCBasic";

    // Actions from JS (alphabetical please)
    private static final String PRESENT_AUTHORIZATION_REQUEST_ACTION = "presentAuthorizationRequest";
    private static final String PRESENT_END_SESSION_REQUEST_ACTION = "presentEndSessionRequest";

    // Params from JS (alphabetical please)
    private static final String ADDITIONAL_PARAMETERS_PARAM = "additionalParameters";
    private static final String ADDITIONAL_PARAMETERS_DISPLAY_PARAM = "display";
    private static final String ADDITIONAL_PARAMETERS_LOGIN_HINT_PARAM = "login_hint";
    private static final String ADDITIONAL_PARAMETERS_PROMPT_PARAM = "prompt";
    private static final String ADDITIONAL_PARAMETERS_RESPONSE_MODE_PARAM = "response_mode";
    private static final String CONFIGURATION_PARAM = "configuration";
    private static final String CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM = "authorizationEndpoint";
    private static final String CLIENT_ID_PARAM = "clientId";
    private static final String REDIRECT_URL_PARAM = "redirectUrl";
    private static final String RESPONSE_TYPE_PARAM = "responseType";
    private static final String SCOPE_PARAM = "scope";
    private static final String STATE_PARAM = "state";

    // Error types
    private static final String UNSENDABLE_REQUEST = "OIDC_UNSENDABLE_REQUEST";
    private static final String ERROR_RESPONSE = "OIDC_ERROR_RESPONSE";
    private static final String INVALID_RESPONSE = "OIDC_INVALID_RESPONSE";
    private static final String HTTP_ERROR = "OIDC_HTTP_ERROR";
    private static final String USER_CANCELLED = "OIDC_USER_CANCELLED";
    private static final String UNEXPECTED_ERROR = "OIDC_UNEXPECTED_ERROR";

    private static final String QUERY_KEY_NONCE = "nonce";

    private static final int REQUEST_CODE = 20609;

    private ExternalUserAgentFlow currentAuthorizationFlow;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        try {
            if (PRESENT_AUTHORIZATION_REQUEST_ACTION.equals(action)) {
                presentAuthorizationRequest(args, callbackContext);
            } else if (PRESENT_END_SESSION_REQUEST_ACTION.equals(action)) {
                presentEndSessionRequest(args, callbackContext);
            } else {
                return false;
            }
        } catch (Exception ex) {
            LOG.e(LOG_TAG, String.format("Unexpected exception: %s", ex.getMessage()), ex);
            JSONObject json = standardJSONForException(ex, UNEXPECTED_ERROR);
            callbackContext.error(json);
        }
        return true;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (requestCode == REQUEST_CODE) {
            if (currentAuthorizationFlow == null) {
                LOG.w(LOG_TAG, "Received activity result (requestCode: %d, resultCode: %d) but no authorization flow is in progress", requestCode, resultCode);
            } else {
                ExternalUserAgentFlow flow = currentAuthorizationFlow;
                currentAuthorizationFlow = null;
                try {
                    flow.finish(intent);
                } catch (Exception ex) {
                    try {
                        LOG.e(LOG_TAG, String.format("Unexpected exception: %s", ex.getMessage()), ex);
                        JSONObject json = standardJSONForException(ex, UNEXPECTED_ERROR);
                        flow.callbackContext.error(json);
                    } catch (JSONException ex2) {
                        // This should never happen
                        LOG.e(LOG_TAG, String.format("Unexpected JSONException: %s", ex2.getMessage()), ex2);
                    }
                }
            }
        } else {
            LOG.w(LOG_TAG, "Received activity result (requestCode: %d, resultCode: %d) but expected requestCode %d", requestCode, resultCode, REQUEST_CODE);
        }
    }

    private void presentAuthorizationRequest(JSONArray args, CallbackContext callbackContext) throws JSONException {
        JSONObject reqParams = args.getJSONObject(0);

        List<String> validationErrors = new ArrayList<>();
        if (!validateAuthorizationRequestParams(reqParams, validationErrors)) {
            LOG.e(LOG_TAG, "Invalid request params: %s", TextUtils.join(", ", validationErrors));
            JSONObject json = jsonForRequestValidationErrors(validationErrors);
            callbackContext.error(json);
            return;
        }

        LOG.d(LOG_TAG, "Preparing AppAuth authorization request");
        AuthorizationRequest request = authorizationRequestForJSParams(reqParams);
        AuthorizationService authService = new AuthorizationService(cordova.getContext());
        launchExternalUserAgentFlow(new AuthorizationRequestFlow(request, authService, callbackContext));
    }

    private boolean validateAuthorizationRequestParams(JSONObject reqParams, List<String> errors) throws JSONException {
        int initSize = errors.size();
        if (reqParams.isNull(CONFIGURATION_PARAM)) {
            errors.add(String.format("%s param is required", CONFIGURATION_PARAM));
        } else {
            if (!(reqParams.get(CONFIGURATION_PARAM) instanceof JSONObject)) {
                errors.add(String.format("%s param must be a JS object", CONFIGURATION_PARAM));
            } else {
                JSONObject configParams = reqParams.getJSONObject(CONFIGURATION_PARAM);
                if (configParams.isNull(CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM)) {
                    errors.add(String.format("%s.%s param is required", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM));
                } else if (!(configParams.get(CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM) instanceof String)) {
                    errors.add(String.format("%s.%s param must be a string", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM));
                } else if (!isValidWebUrl(configParams.getString(CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM))) {
                    errors.add(String.format("%s.%s param must be a valid URL", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM));
                }
            }
        }
        if (reqParams.isNull(RESPONSE_TYPE_PARAM)) {
            errors.add(String.format("%s param is required", RESPONSE_TYPE_PARAM));
        } else if (!(reqParams.get(RESPONSE_TYPE_PARAM) instanceof String)) {
            errors.add(String.format("%s param must be a string", RESPONSE_TYPE_PARAM));
        }
        if (reqParams.isNull(CLIENT_ID_PARAM)) {
            errors.add(String.format("%s param is required", CLIENT_ID_PARAM));
        } else if (!(reqParams.get(CLIENT_ID_PARAM) instanceof String)) {
            errors.add(String.format("%s param must be a string", CLIENT_ID_PARAM));
        }
        if (!reqParams.isNull(SCOPE_PARAM) && !(reqParams.get(SCOPE_PARAM) instanceof String)) {
            errors.add(String.format("%s param must be a string", SCOPE_PARAM));
        }
        if (!reqParams.isNull(REDIRECT_URL_PARAM)) {
            if (!(reqParams.get(REDIRECT_URL_PARAM) instanceof String)) {
                errors.add(String.format("%s param must be a string", REDIRECT_URL_PARAM));
            }
            // On other platforms, we also check that redirectUrl is a valid URL here. But our
            // isValidWebUrl rejects custom schemes (see note in method declaration below),
            // which we definitely want to support. For now just skip the URL validation.
        }
        if (!reqParams.isNull(STATE_PARAM) && !(reqParams.get(STATE_PARAM) instanceof String)) {
            errors.add(String.format("%s param must be a string", STATE_PARAM));
        }
        if (!reqParams.isNull(ADDITIONAL_PARAMETERS_PARAM) && !(reqParams.get(ADDITIONAL_PARAMETERS_PARAM) instanceof JSONObject)) {
            errors.add(String.format("%s param must be a JS object", ADDITIONAL_PARAMETERS_PARAM));
        }

        return errors.size() == initSize;
    }

    private AuthorizationRequest authorizationRequestForJSParams(JSONObject reqParams) throws JSONException {
        JSONObject configParams = reqParams.getJSONObject(CONFIGURATION_PARAM);
        Uri authorizationEndpoint = Uri.parse(configParams.getString(CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM));
        // This is sort of silly: AppAuth requires us to pass a tokenEndpoint and marks the
        // tokenEndpoint param as non-nullable. But the tokenEndpoint isn't actually hit in
        // the course of presenting an authorization request. So, to avoid making calling
        // code pass a dummy tokenEndpoint too, just use the authorizationEndpoint as BOTH
        // the authorizationEndpoint and tokenEndpoint, even though that's blatantly wrong
        // for the tokenEndpoint.
        AuthorizationServiceConfiguration config = new AuthorizationServiceConfiguration(authorizationEndpoint, authorizationEndpoint);
        AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
            config,
            reqParams.getString(CLIENT_ID_PARAM),
            reqParams.getString(RESPONSE_TYPE_PARAM),
            Uri.parse(reqParams.getString(REDIRECT_URL_PARAM))
        );
        // If JS passed in state, use that, otherwise keep the random state value that
        // the AuthorizationRequest.Builder constructor generates automatically.
        if (!reqParams.isNull(STATE_PARAM)) {
            builder.setState(reqParams.getString(STATE_PARAM));
        }
        JSONObject rawAdditionalParams = reqParams.optJSONObject(ADDITIONAL_PARAMETERS_PARAM);
        return builder
            .setScope(reqParams.getString(SCOPE_PARAM))
            // display, loginHint, prompt, and responseMode -- We treat these as
            // additionalParameters, but AppAuth has dedicated properties for these and
            // throws if you try to set them as additionalParameters. Extract value from
            // passed-in additionalParameters, if any.
            .setDisplay(rawAdditionalParams == null ? null : readNullableString(rawAdditionalParams, ADDITIONAL_PARAMETERS_DISPLAY_PARAM))
            .setLoginHint(rawAdditionalParams == null ? null : readNullableString(rawAdditionalParams, ADDITIONAL_PARAMETERS_LOGIN_HINT_PARAM))
            .setPrompt(rawAdditionalParams == null ? null : readNullableString(rawAdditionalParams, ADDITIONAL_PARAMETERS_PROMPT_PARAM))
            .setResponseMode(rawAdditionalParams == null ? null : readNullableString(rawAdditionalParams, ADDITIONAL_PARAMETERS_RESPONSE_MODE_PARAM))
            .setAdditionalParameters(toAppAuthAdditionalAuthReqParams(rawAdditionalParams))
            .build();
    }

    private static final String[] BLACKLISTED_AUTH_REQ_ADDITIONAL_PARAMS = {
        "scope",
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        QUERY_KEY_NONCE,
        "code_challenge",
        "code_challenge_method",
        ADDITIONAL_PARAMETERS_DISPLAY_PARAM,
        ADDITIONAL_PARAMETERS_LOGIN_HINT_PARAM,
        ADDITIONAL_PARAMETERS_PROMPT_PARAM,
        ADDITIONAL_PARAMETERS_RESPONSE_MODE_PARAM
    };

    private Map<String, String> toAppAuthAdditionalAuthReqParams(JSONObject rawAdditionalParams) throws JSONException {
        Map<String, String> out = toAppAuthAdditionalParams(rawAdditionalParams, BLACKLISTED_AUTH_REQ_ADDITIONAL_PARAMS);
        // Surprisingly, the current release version of AppAuth-Android (0.7.1) doesn't
        // generate nonce or even have a dedicated AuthorizationRequest field for it, although
        // current master branch does both. See
        // https://github.com/openid/AppAuth-Android/blob/0.7.1/library/java/net/openid/appauth/AuthorizationRequest.java
        // (0.7.1) vs
        // https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/AuthorizationRequest.java
        // (master) and search "nonce" to see the difference.
        // So, for now, we'll generate nonce ourselves, using the same method that AppAuth-Android
        // master branch does, and add it as an additional param.
        out.put(QUERY_KEY_NONCE, generateRandomString(16));
        return out;
    }

    private class AuthorizationRequestFlow extends ExternalUserAgentFlow {
        public final AuthorizationRequest request;
        public final AuthorizationService authService;

        public AuthorizationRequestFlow(AuthorizationRequest request, AuthorizationService authService, CallbackContext callbackContext) {
            super(authService.getAuthorizationRequestIntent(request), callbackContext);
            this.request = request;
            this.authService = authService;
        }

        @Override
        public void finish(Intent data) throws JSONException {
            // Instances of AuthorizationService must be manually disposed.
            // See https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/AuthorizationService.java
            // and https://github.com/openid/AppAuth-Android/issues/91
            if (authService != null) authService.dispose();

            AuthorizationResponse resp = AuthorizationResponse.fromIntent(data);
            if (resp != null) {
                LOG.d(LOG_TAG, "Authorization success response");
                JSONObject json = jsonForSuccessfulAuthorizationResponse(resp);
                callbackContext.success(json);
            } else {
                AuthorizationException ex = AuthorizationException.fromIntent(data);
                JSONObject json;
                if (ex.type == AuthorizationException.TYPE_OAUTH_AUTHORIZATION_ERROR) {
                    List<String> validationErrors = new ArrayList<>();
                    if (validateAuthorizationErrorResponse(ex, request, validationErrors)) {
                        LOG.e(LOG_TAG, String.format("Authorization error response: %s", ex.getMessage()), ex);
                        json = jsonForAuthorizationErrorResponse(ex, request);
                    } else {
                        LOG.e(LOG_TAG, "Invalid authorization error response: %s", TextUtils.join(", ", validationErrors));
                        json = jsonForInvalidAuthorizationErrorResponse(validationErrors);
                    }
                } else {
                    LOG.e(LOG_TAG, String.format("Authorization exception: %s", ex.getMessage()), ex);
                    json = jsonForNonErrorResponseAuthorizationException(ex);
                }
                callbackContext.error(json);
            }
        }
    }

    private JSONObject jsonForSuccessfulAuthorizationResponse(AuthorizationResponse response) throws JSONException {
        return new JSONObject()
            .put("request",                      jsonForNullable(jsonForReturnedAuthorizationRequest(response.request)))
            .put("authorizationCode",            jsonForNullable(response.authorizationCode))
            .put("state",                        jsonForNullable(response.state))
            .put("accessToken",                  jsonForNullable(response.accessToken))
            .put("accessTokenExpirationDate",    jsonForNullable(response.accessTokenExpirationTime))
            .put("tokenType",                    jsonForNullable(response.tokenType))
            .put("idToken",                      jsonForNullable(response.idToken))
            .put("scope",                        jsonForNullable(response.scope))
            .put("additionalParameters",         jsonForMap(response.additionalParameters));
    }

    // We return the request back to JS b/c AppAuth populates additional params on the request that calling
    // code might need to perform the code exchange, e.g. nonce, codeVerifier.
    private JSONObject jsonForReturnedAuthorizationRequest(AuthorizationRequest request) throws JSONException {
        if (request == null) return null;
        return new JSONObject()
            .put("responseType",               jsonForNullable(request.responseType))
            .put("clientId",                   jsonForNullable(request.clientId))
            .put("scope",                      jsonForNullable(request.scope))
            .put("redirectUrl",                jsonForNullable(request.redirectUri == null ? null : request.redirectUri.toString()))
            .put("state",                      jsonForNullable(request.state))
            // For now, get nonce from additionalParameters. See comment in
            // toAppAuthAdditionalAuthReqParams above.
            .put("nonce",                      jsonForNullable(request.additionalParameters.get(QUERY_KEY_NONCE)))
            .put("codeVerifier",               jsonForNullable(request.codeVerifier))
            .put("codeChallenge",              jsonForNullable(request.codeVerifierChallenge))
            .put("codeChallengeMethod",        jsonForNullable(request.codeVerifierChallengeMethod))
            .put("additionalParameters",       jsonForMap(getAdditionalParamsForReturnedAuthorizationRequest(request)));
    }

    private Map<String, String> getAdditionalParamsForReturnedAuthorizationRequest(AuthorizationRequest request) throws JSONException {
        // Reverse the additionalParameters munging we did in authorizationRequestForJSParams....

        Map<String, String> additionalParams = new HashMap<>(request.additionalParameters);

        // ....We pulled display, loginHint, prompt, and responseMode out of additional params
        // above, so put them back in.
        if (request.display != null) additionalParams.put(ADDITIONAL_PARAMETERS_DISPLAY_PARAM, request.display);
        if (request.loginHint != null) additionalParams.put(ADDITIONAL_PARAMETERS_LOGIN_HINT_PARAM, request.loginHint);
        if (request.prompt != null) additionalParams.put(ADDITIONAL_PARAMETERS_PROMPT_PARAM, request.prompt);
        if (request.responseMode != null) additionalParams.put(ADDITIONAL_PARAMETERS_RESPONSE_MODE_PARAM, request.responseMode);

        // ....And we added nonce to additional params, but we have a dedicated property for it
        // on our returned auth req, so remove it.
        additionalParams.remove(QUERY_KEY_NONCE);

        return additionalParams;
    }

    private boolean validateAuthorizationErrorResponse(AuthorizationException resp, AuthorizationRequest request, List<String> errors) {
        int initSize = errors.size();

        // Hmm... Like AppAuth-iOS and unlike AppAuth-JS, AppAuth-Android goes down its code
        // path for error responses BEFORE validating the returned state.
        // See https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/AuthorizationManagementActivity.java
        // (search "Intent extractResponseData").
        // So it'd be nice to validate that the error response state matches the request state here.
        // See the -validateAuthorizationErrorResponse:request:errors: method in
        // ./ios/OIDCBasic.m for the iOS version of that logic.
        // The problem is, unlike AppAuth-iOS, AppAuth-Android swallows all details from the
        // error response except error, error_description, and error_uri, meaning we no longer
        // have the error response state to compare against.
        // See https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/AuthorizationException.java
        // (search "fromOAuthRedirect").
        // So we really have no choice here but to accept AppAuth-Android's behavior and
        // skip state validation for error responses. This is a behavior difference btwn
        // Android and our other platforms.

        return errors.size() == initSize;
    }

    private JSONObject jsonForAuthorizationErrorResponse(AuthorizationException response, AuthorizationRequest request) throws JSONException {
        JSONObject respJSON = responseJSONForAuthorizationErrorResponse(response, request);
        return new JSONObject()
            .put("type",         ERROR_RESPONSE)
            .put("message",      respJSON.get("error"))
            .put("details",      respJSON.get("errorDescription"))
            .put("response",     respJSON);
    }

    private JSONObject responseJSONForAuthorizationErrorResponse(AuthorizationException response, AuthorizationRequest request) throws JSONException {
        return new JSONObject()
            .put("request",            jsonForNullable(jsonForReturnedAuthorizationRequest(request)))
            .put("error",              jsonForNullable(response.error))
            .put("errorDescription",   jsonForNullable(response.errorDescription))
            .put("errorUrl",           jsonForNullable(response.errorUri == null ? null : response.errorUri.toString()))
            // AppAuth-Android unfortunately doesn't expose state for error responses.
            // Explicitly set to null (instead of just leaving undefined).
            .put("state",              JSONObject.NULL);
    }

    private JSONObject jsonForInvalidAuthorizationErrorResponse(List<String> validationErrors) throws JSONException {
        String message = String.format("Invalid response: %s", TextUtils.join(", ", validationErrors));
        return new JSONObject()
            .put("type",        INVALID_RESPONSE)
            .put("message",     message)
            .put("details",     message);
    }

    private JSONObject jsonForNonErrorResponseAuthorizationException(AuthorizationException ex) throws JSONException {
        if (ex.type == AuthorizationException.TYPE_GENERAL_ERROR) {
            // Weirdly, AppAuth classifies STATE_MISMATCH as a general error, based on its type,
            // but declares the constant under AuthorizationRequestErrors.
            if (ex.code == AuthorizationException.AuthorizationRequestErrors.STATE_MISMATCH.code) {
                // STATE_MISMATCH means response state param was invalid. Call that INVALID_RESPONSE.
                return standardJSONForException(ex, INVALID_RESPONSE);
            } else if (ex.code == AuthorizationException.GeneralErrors.NETWORK_ERROR.code) {
                return standardJSONForException(ex, HTTP_ERROR);
            } else if (ex.code == AuthorizationException.GeneralErrors.USER_CANCELED_AUTH_FLOW.code) {
                return standardJSONForException(ex, USER_CANCELLED);
            }
        }

        return standardJSONForException(ex, UNEXPECTED_ERROR);
    }

    private void presentEndSessionRequest(JSONArray args, CallbackContext callbackContext) throws JSONException {
        // Currently, AppAuth-Android just doesn't support sending end session requests.
        // See https://github.com/openid/AppAuth-Android/issues/374 (opened 7/17/2018).
        // So we just won't attempt to support presentEndSessionRequest on Android.
        JSONObject error = new JSONObject()
            .put("type",        UNSENDABLE_REQUEST)
            .put("message",     "End session requests aren't supported on Android b/c AppAuth-Android support is missing. See https://github.com/openid/AppAuth-Android/issues/374")
            .put("details",     "End session requests aren't supported on Android b/c AppAuth-Android support is missing. See https://github.com/openid/AppAuth-Android/issues/374");
        callbackContext.error(error);
    }

    // NOTE: If we AppAuth-Android someday adds end session support, then we'll wanna add
    // code for end session requests parallel to what we have for authorization requests.

    private void launchExternalUserAgentFlow(ExternalUserAgentFlow flow) throws JSONException {
        // Bail if an external user agent flow is already in progress
        if (currentAuthorizationFlow != null) {
            LOG.e(LOG_TAG, "Another authorization flow is already in progress.");
            JSONObject json = jsonForAuthorizationFlowAlreadyInProgress();
            flow.callbackContext.error(json);
            return;
        }

        LOG.d(LOG_TAG, "Launching authorization flow");
        currentAuthorizationFlow = flow;
        flow.start();
    }

    private abstract class ExternalUserAgentFlow {
        public final Intent launchAgentIntent;
        public final CallbackContext callbackContext;

        public ExternalUserAgentFlow(Intent launchAgentIntent, CallbackContext callbackContext) {
            this.launchAgentIntent = launchAgentIntent;
            this.callbackContext = callbackContext;
        }

        public void start() {
            cordova.startActivityForResult(OIDCBasic.this, launchAgentIntent, REQUEST_CODE);
        }

        public abstract void finish(Intent data) throws JSONException;
    }

    private boolean isValidWebUrl(String url) {
        if (url == null) return false;

        // See https://stackoverflow.com/a/5930532.
        // Note that this excludes custom schemes, see
        // https://github.com/aosp-mirror/platform_frameworks_base/blob/master/core/java/android/util/Patterns.java
        // (search "Pattern WEB_URL" and "String PROTOCOL").
        return Patterns.WEB_URL.matcher(url).matches();
    }

    // JSONObject's optString has a few annoying behaviors. For one, if you call like
    // obj.optString("key") and the key is just plain missing, you get back the empty
    // string instead of null. And even if you call like obj.optString("key", null),
    // if the key is present but w/ an explicit null value (i.e. null in the original
    // JSON document, which gets represented in Java as JSONObject.NULL) then you get
    // back the string "null" instead of null. In contrast, this method behaves like:
    // Key missing or present w/ an explicit null value => returns Java null.
    // Key present w/ any other value => Returns value.toString().
    private String readNullableString(JSONObject obj, String key) {
        Object val = obj.opt(key);
        return JSONObject.NULL.equals(val) ? null : val.toString();
    }

    // Turn a JSONObject of additional parameters into a Map<String, String> for passing to AppAuth,
    // removing blacklisted parameters along the way.
    private Map<String, String> toAppAuthAdditionalParams(JSONObject additionalParams, String[] blacklistedParams) {
        Map<String, String> out = new HashMap<>();
        if (additionalParams != null) {
            looponkeys:
            for (Iterator<String> it = additionalParams.keys(); it.hasNext(); ) {
                String key = it.next();
                for (int i = 0; i < blacklistedParams.length; i++) {
                    if (blacklistedParams[i].equals(key)) continue looponkeys;
                }
                // Even though key is present in the additionalParams object, it could still be
                // present w/ a null value. AppAuth throws if any additional param has a null
                // value, so just skip these.
                String val = readNullableString(additionalParams, key);
                if (val != null) out.put(key, val);
            }
        }
        return out;
    }

    private JSONObject jsonForRequestValidationErrors(List<String> validationErrors) throws JSONException {
        String message = String.format("Request contained the following validation errors: %s", TextUtils.join(", ", validationErrors));
        return new JSONObject()
            .put("type",       UNSENDABLE_REQUEST)
            .put("message",    message)
            .put("details",    message);
    }

    private JSONObject jsonForAuthorizationFlowAlreadyInProgress() throws JSONException {
        return new JSONObject()
            .put("type",       UNSENDABLE_REQUEST)
            .put("message",    "Cannot send this request b/c another authorization flow is already in progress.")
            .put("details",    "Cannot send this request b/c another authorization flow is already in progress.");
    }

    private JSONObject standardJSONForException(Exception ex, String type) throws JSONException {
        return new JSONObject()
            .put("type",      type)
            .put("message",   ex.getMessage())
            .put("details",   getStackTraceString(ex));
    }

    private Object jsonForNullable(Object nullable) {
        // JSONObject.put interprets a null value as removing that key, rather than
        // including that key w/ a null value. So we convert to JSONObject.NULL instead.
        return nullable == null ? JSONObject.NULL : nullable;
    }

    private Object jsonForMap(Map<String, String> map) {
        return map == null ? JSONObject.NULL : new JSONObject(map);
    }

    private String generateRandomString(int byteLength) {
        // Taken from AppAuth-Android source. See
        // https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/AuthorizationRequest.java
        // and search "String generateRandomState";
        SecureRandom sr = new SecureRandom();
        byte[] random = new byte[byteLength];
        sr.nextBytes(random);
        return Base64.encodeToString(random, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
    }
}

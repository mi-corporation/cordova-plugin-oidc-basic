#import <objc/runtime.h>
#import <AppAuth/AppAuth.h>
#import "AppDelegate.h"
#import "OIDCBasic.h"

#include <TargetConditionals.h>

// Params from JS (alphabetical please)
static NSString * ADDITIONAL_PARAMETERS_PARAM = @"additionalParameters";
static NSString * CONFIGURATION_PARAM = @"configuration";
static NSString * CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM = @"authorizationEndpoint";
static NSString * CONFIGURATION_END_SESSION_ENDPOINT_PARAM = @"endSessionEndpoint";
static NSString * CLIENT_ID_PARAM = @"clientId";
static NSString * ID_TOKEN_HINT_PARAM = @"idTokenHint";
static NSString * POST_LOGOUT_REDIRECT_URL_PARAM = @"postLogoutRedirectUrl";
static NSString * REDIRECT_URL_PARAM = @"redirectUrl";
static NSString * RESPONSE_TYPE_PARAM = @"responseType";
static NSString * SCOPE_PARAM = @"scope";
static NSString * STATE_PARAM = @"state";

// Error types
static NSString * UNSENDABLE_REQUEST = @"OIDC_UNSENDABLE_REQUEST";
static NSString * ERROR_RESPONSE = @"OIDC_ERROR_RESPONSE";
static NSString * INVALID_RESPONSE = @"OIDC_INVALID_RESPONSE";
static NSString * HTTP_ERROR = @"OIDC_HTTP_ERROR";
static NSString * USER_CANCELLED = @"OIDC_USER_CANCELLED";
static NSString * UNEXPECTED_ERROR = @"OIDC_UNEXPECTED_ERROR";

static NSString * QUERY_KEY_STATE = @"state";

static id<OIDExternalUserAgentSession> currentAuthorizationFlow = nil;

// Have to register to handle redirections. See https://github.com/openid/AppAuth-iOS#authorizing-ios
// Use method swizzling to respect any existing application:openURL:options: implementation.
// NOTE: This registration code is only needed to support iOS 10 and below. Check
// https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuth/iOS/OIDExternalUserAgentIOS.m and
// note the handling for different iOS versions in -presentExternalUserAgentRequest:session:.
// For iOS 11+, that method calls -resumeExternalUserAgentFlowWithURL: itself.
@implementation AppDelegate (OIDCBasicAppDelegate)

-(BOOL)oidcBasicApplication:(UIApplication *)app
                    openURL:(NSURL *)url
                    options:(NSDictionary<NSString *, id> *)options {
    if ([currentAuthorizationFlow resumeExternalUserAgentFlowWithURL:url]) {
        return YES;
    }
    return [self oidcBasicApplication:app openURL:url options:options];
}

static BOOL OpenURLFallback(id self, SEL _cmd, UIApplication *app, NSURL *url, NSDictionary<NSString *, id> *options) {
    return NO;
}

+(void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [self class];
        SEL oidcBasicSel = @selector(oidcBasicApplication:openURL:options:);
        Method override = class_getInstanceMethod(class, oidcBasicSel);
        const char *types = method_getTypeEncoding(override);
        SEL originalSel = @selector(application:openURL:options:);
        // Try adding fallback as the impl for the original selector, in case AppDelegate doesn't
        // have an existing impl of the original selector. But we don't care if this add fails.
        class_addMethod(class, originalSel, (IMP)OpenURLFallback, types);
        Method original = class_getInstanceMethod(class, originalSel);
        method_exchangeImplementations(original, override);
    });
}

@end


@implementation OIDCBasic

// presentAuthorizationRequest

-(void)presentAuthorizationRequest:(CDVInvokedUrlCommand *)command {
    // Jump to background thread to avoid Cordova warnings about blocking the main thread.
    // I suspect generation of state, nonce, codeVerifier, and codeChallenge dominate the CPU time here.
    [self.commandDelegate runInBackground:^{
        NSDictionary * reqParams = [command argumentAtIndex:0 withDefault:nil andClass:[NSDictionary class]];

        NSMutableArray<NSString *> *validationErrors;
        if (![self validateAuthorizationRequestParams:reqParams errors:&validationErrors]) {
            NSDictionary *json = [self jsonForRequestValidationErrors:validationErrors];
            CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            return;
        }

        OIDAuthorizationRequest *request = [self authorizationRequestForJSParams:reqParams];

        [self launchAuthorizationFlowForCommand:command flow:^{
            OIDAuthorizationCallback callback = ^(OIDAuthorizationResponse *response, NSError *error) {
                currentAuthorizationFlow = nil;

                CDVPluginResult *result;
                if (response) {
                    NSDictionary *json = [self jsonForSuccessfulAuthorizationResponse:response];
                    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
                } else {
                    NSDictionary *json;
                    NSDictionary *errResp = [self authorizationErrorResponseFromError:error];
                    if (errResp) {
                        NSMutableArray<NSString *> *errRespValidationErrors;
                        if ([self validateAuthorizationErrorResponse:errResp request:request errors:&errRespValidationErrors]) {
                            json = [self jsonForAuthorizationErrorResponse:errResp request:request];
                        } else {
                            json = [self jsonForInvalidAuthorizationErrorResponse:errRespValidationErrors];
                        }
                    } else {
                        json = [self jsonForNonErrorResponseAuthorizationError:error];
                    }
                    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
                }
                [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            };

            // Initiate the authorizationRequest. NOTE: We call OIDAuthorizationService's
            // -presentAuthorizationRequest:etc directly rather than using OIDAuthState's
            // -authStateByPresentingAuthorizationRequest:etc helper as OIDAuthState assumes the entire
            // flow should be run on device, including the token exchange. Whereas the goal of this plugin
            // is just to expose the authorization request piece of the flow. We may later add a separate
            // method for performing the token exchange on device.
            return [OIDAuthorizationService presentAuthorizationRequest:request
                                               presentingViewController:self.viewController
                                                               callback:callback];
        }];
    }];
}

-(BOOL)validateAuthorizationRequestParams:reqParams
                               errors:(NSMutableArray<NSString *> **)errors {
    NSMutableArray<NSString *> *validationErrors = [[NSMutableArray alloc] init];

    if (!reqParams) {
        [validationErrors addObject:@"request params object is required"];
    } else {
        if (![self isValuePresent:reqParams[CONFIGURATION_PARAM]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param is required", CONFIGURATION_PARAM]];
        } else {
            if (![reqParams[CONFIGURATION_PARAM] isKindOfClass:[NSDictionary class]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a JS object", CONFIGURATION_PARAM]];
            } else {
                NSDictionary *configParams = reqParams[CONFIGURATION_PARAM];
                if (![self isValuePresent:configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param is required", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
                } else if (![configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM] isKindOfClass:[NSString class]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param must be a string", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
                } else if (![NSURL URLWithString:configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param must be a valid URL", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
                }
            }
        }
        if (![self isValuePresent:reqParams[RESPONSE_TYPE_PARAM]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param is required", RESPONSE_TYPE_PARAM]];
        } else if (![reqParams[RESPONSE_TYPE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", RESPONSE_TYPE_PARAM]];
        }
        if (![self isValuePresent:reqParams[CLIENT_ID_PARAM]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param is required", CLIENT_ID_PARAM]];
        } else if (![reqParams[CLIENT_ID_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", CLIENT_ID_PARAM]];
        }
        if ([self isValuePresent:reqParams[SCOPE_PARAM]] && ![reqParams[SCOPE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", SCOPE_PARAM]];
        }
        if ([self isValuePresent:reqParams[REDIRECT_URL_PARAM]]) {
            if (![reqParams[REDIRECT_URL_PARAM] isKindOfClass:[NSString class]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", REDIRECT_URL_PARAM]];
            } else if (![NSURL URLWithString:reqParams[REDIRECT_URL_PARAM]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a valid URL", REDIRECT_URL_PARAM]];
            }
        }
        if ([self isValuePresent:reqParams[STATE_PARAM]] && ![reqParams[STATE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", STATE_PARAM]];
        }
        if ([self isValuePresent:reqParams[ADDITIONAL_PARAMETERS_PARAM]] && ![reqParams[ADDITIONAL_PARAMETERS_PARAM] isKindOfClass:[NSDictionary class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a JS object", ADDITIONAL_PARAMETERS_PARAM]];
        }
    }

    *errors = validationErrors;
    return validationErrors.count == 0;
}

-(OIDAuthorizationRequest *)authorizationRequestForJSParams:(NSDictionary *)reqParams {
    NSDictionary *configParams = reqParams[CONFIGURATION_PARAM];
    NSURL *authorizationEndpoint = [NSURL URLWithString:configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
    // This is sort of silly: AppAuth requires us to pass a tokenEndpoint and marks the
    // OIDServiceConfiguration.tokenEndpoint property as non-nullable. But the tokenEndpoint isn't
    // actually hit in the course of presenting an authorization request. So, to avoid making calling
    // code pass a dummy tokenEndpoint too, just use the authorizationEndpoint as BOTH the
    // authorizationEndpoint and tokenEndpoint, even though that's blatantly wrong for the
    // tokenEndpoint.
    OIDServiceConfiguration *config =
        [[OIDServiceConfiguration alloc] initWithAuthorizationEndpoint:authorizationEndpoint
                                                         tokenEndpoint:authorizationEndpoint];

    // We can't use the opionated OIDAuthorizationRequest initializer that generates nonce, state, and
    // params needed for PKCE (codeVerifier, codeChallenge, and codeChallengeMethod), b/c we want to
    // let JS pass state, and OIDAuthorizationRequest.state is readonly, so we can't modify it post
    // initialization. So generate nonce, codeVerifier, codeChallenge, exactly as the opinionated
    // initalizer does. See https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuthCore/OIDAuthorizationRequest.m
    NSString *nonce = [OIDAuthorizationRequest generateState];
    NSString *codeVerifier = [OIDAuthorizationRequest generateCodeVerifier];
    NSString *codeChallenge = [OIDAuthorizationRequest codeChallengeS256ForVerifier:codeVerifier];
    // If JS passed in state, use that, otherwise generate state exactly as the opinionated
    // initializer does. This is needed to support the use case of calling code encoding current UI
    // state or other info in the state param. But it also means calling code has the responsibility
    // for using the state param correctly. In particular, the spec says that clients SHOULD make
    // their state param opaque and non-guessable. See https://tools.ietf.org/html/rfc6749#section-10.12.
    // (For what it's worth, I think that section applies more closely to web apps and that for native
    // apps PKCE defends against the same attacks in a more robust way. But I'd still recommend
    // calling code make their state opaque and non-guessable as an extra security measure.)
    NSString *state = [self coerceNSNullToNil:reqParams[STATE_PARAM]] ?: [OIDAuthorizationRequest generateState];
    return [[OIDAuthorizationRequest alloc] initWithConfiguration:config
                                                         clientId:reqParams[CLIENT_ID_PARAM]
                                                     clientSecret:nil
                                                            scope:[self coerceNSNullToNil:reqParams[SCOPE_PARAM]]
                                                      redirectURL:[NSURL URLWithString:[self coerceNSNullToNil:reqParams[REDIRECT_URL_PARAM]]]
                                                     responseType:reqParams[RESPONSE_TYPE_PARAM]
                                                            state:state
                                                            nonce:nonce
                                                     codeVerifier:codeVerifier
                                                    codeChallenge:codeChallenge
                                              codeChallengeMethod:OIDOAuthorizationRequestCodeChallengeMethodS256
                                             additionalParameters:[self preprocessAuthorizationRequestAdditionalParams:reqParams[ADDITIONAL_PARAMETERS_PARAM]]];
}

// Pre-process additional parameters so that regardless of AppAuth behavior, we'll
// enforce the behavior that known parameters must be set via the documented
// params rather than additionalParameters param.
-(NSDictionary<NSString *, NSString *> *)preprocessAuthorizationRequestAdditionalParams:(NSDictionary<NSString *, NSString *> *)params {
    static NSString * const BLACKLISTED[] = {
        @"scope",
        @"response_type",
        @"client_id",
        @"redirect_uri",
        @"state",
        @"nonce",
        @"code_challenge",
        @"code_challenge_method"
    };

    static int BLACKLISTED_LENGTH = sizeof(BLACKLISTED) / sizeof(BLACKLISTED[0]);

    if ([self isValuePresent:params]) {
        NSMutableDictionary *processed = [[NSMutableDictionary alloc] initWithDictionary:params];
        for (int i = 0; i < BLACKLISTED_LENGTH; i++) {
            [processed removeObjectForKey:BLACKLISTED[i]];
        }
        return processed;
    } else {
        return nil;
    }
}

-(NSDictionary *)jsonForSuccessfulAuthorizationResponse:(OIDAuthorizationResponse *)response {
    if (!response) return nil;
    return @{
        @"request":                      [self jsonForNilable:[self jsonForReturnedAuthorizationRequest:response.request]],
        @"authorizationCode":            [self jsonForNilable:response.authorizationCode],
        @"state":                        [self jsonForNilable:response.state],
        @"accessToken":                  [self jsonForNilable:response.accessToken],
        @"accesTokenExpirationDate":     [self jsonForDate:response.accessTokenExpirationDate],
        @"tokenType":                    [self jsonForNilable:response.tokenType],
        @"idToken":                      [self jsonForNilable:response.idToken],
        @"scope":                        [self jsonForNilable:response.scope],
        @"additionalParameters":         [self jsonForNilable:response.additionalParameters]
    };
}

// We return the request back to JS b/c AppAuth populates additional params on the request that calling
// code might need to perform the code exchange, e.g. nonce, codeVerifier.
-(NSDictionary *)jsonForReturnedAuthorizationRequest:(OIDAuthorizationRequest *)request {
    if (!request) return nil;
    return @{
        // Don't pass back the configuration. Nothing interesting can happen to it.
        @"responseType":               [self jsonForNilable:request.responseType],
        @"clientId":                   [self jsonForNilable:request.clientID],
        @"scope":                      [self jsonForNilable:request.scope],
        @"redirectUrl":                [self jsonForNilable:request.redirectURL.absoluteString],
        @"state":                      [self jsonForNilable:request.state],
        @"nonce":                      [self jsonForNilable:request.nonce],
        @"codeVerifier":               [self jsonForNilable:request.codeVerifier],
        @"codeChallenge":              [self jsonForNilable:request.codeChallenge],
        @"codeChallengeMethod":        [self jsonForNilable:request.codeChallengeMethod],
        @"additionalParameters":       [self jsonForNilable:request.additionalParameters]
    };
}

-(NSDictionary *)authorizationErrorResponseFromError:(NSError *)error {
    return [error.domain isEqualToString:OIDOAuthAuthorizationErrorDomain] ? [self coerceNSNullToNil:error.userInfo[OIDOAuthErrorResponseErrorKey]] : nil;
}

-(BOOL)validateAuthorizationErrorResponse:(NSDictionary *)response
                                  request:(OIDAuthorizationRequest *)request
                                   errors:(NSMutableArray<NSString *> **)errors {
    NSMutableArray<NSString *> *validationErrors = [[NSMutableArray alloc] init];

    // Validate that the response state matches the request state, even for error responses.
    // AppAuth-iOS doesn't do this itself: See
    // https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuthCore/OIDAuthorizationService.m
    // (search "RFC6749 Section 4.1.2.1") and
    // https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuthCore/OIDErrorUtilities.m (search
    // "OAuthResponse:"). This appears to be a behavior difference btwn AppAuth-iOS, which
    // proceeds down its code path for error responses BEFORE validating the returned state, vs
    // AppAuth-JS, which validates the returned state BEFORE detecting error responses. See
    // https://github.com/openid/AppAuth-JS/blob/master/src/redirect_based_handler.ts (search
    // "let shouldNotify").
    // We'll converge on the AppAuth-JS behavior b/c it seems more consistent w/ the spec
    // (https://tools.ietf.org/html/rfc6749#section-4.1.2.1):
    //
    //   state
    //         REQUIRED if a "state" parameter was present in the client
    //         authorization request.  The exact value received from the
    //         client.
    //
    // I.e. any compliant server must return the exact state value provided. Validating state also
    // helps defend against the possibility (perhaps remote) that malicious code might try to fool us
    // by injecting a forged error response.
    if (request.state) {
        // Request has non-nil state. Response state should be a string that matches exactly
        if (![self isValuePresent:response[QUERY_KEY_STATE]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"Missing query key '%@'", QUERY_KEY_STATE]];
        } else if (![response[QUERY_KEY_STATE] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"Unexpected value type %@ for query key '%@'. Expected NSString.", [response[QUERY_KEY_STATE] class], QUERY_KEY_STATE]];
        } else if (![request.state isEqualToString:response[QUERY_KEY_STATE]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"State mismatch: Expected '%@' but found '%@'", request.state, response[QUERY_KEY_STATE]]];
        }
    } else if ([self isValuePresent:response[QUERY_KEY_STATE]]) {
        // Response unexpectedly has state even though request didnt.
        [validationErrors addObject:[NSString stringWithFormat:@"State mismatch: Expected %@ but found %@", request.state, response[QUERY_KEY_STATE]]];
    }

    *errors = validationErrors;
    return validationErrors.count == 0;
}

-(NSDictionary *)jsonForAuthorizationErrorResponse:(NSDictionary *)response
                                           request:(OIDAuthorizationRequest *)request {
    NSDictionary *respJson = [self responseJsonForAuthorizationErrorResponse:response request:request];
    return @{
        @"type":         ERROR_RESPONSE,
        @"message":      respJson[@"error"],
        @"details":      respJson[@"errorDescription"],
        @"response":     respJson
    };
}

-(NSDictionary *)responseJsonForAuthorizationErrorResponse:(NSDictionary *)response
                                                   request:(OIDAuthorizationRequest *)request {
    return @{
        @"request":               [self jsonForNilable:[self jsonForReturnedAuthorizationRequest:request]],
        @"error":                 [self maybeString:response[OIDOAuthErrorFieldError]],
        @"errorDescription":      [self maybeString:response[OIDOAuthErrorFieldErrorDescription]],
        @"errorUrl":              [self maybeString:response[OIDOAuthErrorFieldErrorURI]],
        @"state":                 [self maybeString:response[QUERY_KEY_STATE]]
    };
}

-(NSDictionary *)jsonForInvalidAuthorizationErrorResponse:(NSArray<NSString *> *)validationErrors {
    NSString *message = [@"Invalid response: " stringByAppendingString:[validationErrors componentsJoinedByString:@", "]];
    return @{
        @"type":         INVALID_RESPONSE,
        @"message":      message,
        @"details":      message
    };
}

-(NSDictionary *)jsonForNonErrorResponseAuthorizationError:(NSError *)error {
    if ([error.domain isEqualToString:OIDOAuthAuthorizationErrorDomain]) {
        if (error.code == OIDErrorCodeOAuthAuthorizationClientError) {
            // The OIDErrorCodeOAuthAuthorizationClientError constant seems misleading to me.
            // AppAuth returns this error when the response doesn't meet our expectations, meaning
            // the PROVIDER did something not in keeping w/ our understanding of OIDC (or that
            // a malicious party tried to modify the provider's response). Either way call that
            // an INVALID_RESPONSE.
            return [self standardJSONForError:error type:INVALID_RESPONSE];
        }
    } else if ([error.domain isEqualToString:OIDGeneralErrorDomain]) {
        if (error.code == OIDErrorCodeNetworkError) {
            return [self standardJSONForError:error type:HTTP_ERROR];
        } else if (error.code == OIDErrorCodeUserCanceledAuthorizationFlow) {
            return [self standardJSONForError:error type:USER_CANCELLED];
        }
    }

    return [self standardJSONForError:error type:UNEXPECTED_ERROR];
}

// presentEndSessionRequest

-(void)presentEndSessionRequest:(CDVInvokedUrlCommand *)command {
    // Jump to background thread to avoid Cordova warnings about blocking the main thread.
    [self.commandDelegate runInBackground:^{
        NSDictionary * reqParams = [command argumentAtIndex:0 withDefault:nil andClass:[NSDictionary class]];

        NSMutableArray<NSString *> *validationErrors;
        if (![self validateEndSessionRequestParams:reqParams errors:&validationErrors]) {
            NSDictionary *json = [self jsonForRequestValidationErrors:validationErrors];
            CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            return;
        }

        OIDEndSessionRequest *request = [self endSessionRequestForJSParams:reqParams];

        [self launchAuthorizationFlowForCommand:command flow:^{
            OIDEndSessionCallback callback = ^(OIDEndSessionResponse *response, NSError *error) {
                currentAuthorizationFlow = nil;

                CDVPluginResult *result;
                if (response) {
                    NSDictionary *json = [self jsonForEndSessionResponse:response];
                    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
                } else {
                    NSDictionary *json = [self jsonForEndSessionError:error];
                    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
                }
                [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            };

            return [self presentEndSessionRequest:request callback:callback];
        }];
    }];
}

-(id<OIDExternalUserAgentSession>)presentEndSessionRequest:(OIDEndSessionRequest *)request
                                                  callback:(OIDEndSessionCallback)callback {
    // Unlike for authorizationRequests, AppAuth doesn't expose a nice
    // -presentEndSessionRequest:presentingViewController:callback: method for iOS. So we're inlining
    // the equivalent logic here.
    // See https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuth/iOS/OIDAuthorizationService%2BIOS.m
    id<OIDExternalUserAgent> externalUserAgent;
#if TARGET_OS_MACCATALYST
  externalUserAgent = [[OIDExternalUserAgentCatalyst alloc] initWithPresentingViewController:self.viewController];
#else // TARGET_OS_MACCATALYST
  externalUserAgent = [[OIDExternalUserAgentIOS alloc] initWithPresentingViewController:self.viewController];
#endif // TARGET_OS_MACCATALYST
    return [OIDAuthorizationService presentEndSessionRequest:request externalUserAgent:externalUserAgent callback:callback];
}

-(BOOL)validateEndSessionRequestParams:reqParams
                                errors:(NSMutableArray<NSString *> **)errors {
    NSMutableArray<NSString *> *validationErrors = [[NSMutableArray alloc] init];

    if (!reqParams) {
        [validationErrors addObject:@"request params object is required"];
    } else {
        if (![self isValuePresent:reqParams[CONFIGURATION_PARAM]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param is required", CONFIGURATION_PARAM]];
        } else {
            if (![reqParams[CONFIGURATION_PARAM] isKindOfClass:[NSDictionary class]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a JS object", CONFIGURATION_PARAM]];
            } else {
                NSDictionary *configParams = reqParams[CONFIGURATION_PARAM];
                if (![self isValuePresent:configParams[CONFIGURATION_END_SESSION_ENDPOINT_PARAM]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param is required", CONFIGURATION_PARAM, CONFIGURATION_END_SESSION_ENDPOINT_PARAM]];
                } else if (![configParams[CONFIGURATION_END_SESSION_ENDPOINT_PARAM] isKindOfClass:[NSString class]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param must be a string", CONFIGURATION_PARAM, CONFIGURATION_END_SESSION_ENDPOINT_PARAM]];
                } else if (![NSURL URLWithString:configParams[CONFIGURATION_END_SESSION_ENDPOINT_PARAM]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param must be a valid URL", CONFIGURATION_PARAM, CONFIGURATION_END_SESSION_ENDPOINT_PARAM]];
                }
            }
        }
        if ([self isValuePresent:reqParams[POST_LOGOUT_REDIRECT_URL_PARAM]]) {
            if (![reqParams[POST_LOGOUT_REDIRECT_URL_PARAM] isKindOfClass:[NSString class]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", POST_LOGOUT_REDIRECT_URL_PARAM]];
            } else if (![NSURL URLWithString:reqParams[POST_LOGOUT_REDIRECT_URL_PARAM]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a valid URL", POST_LOGOUT_REDIRECT_URL_PARAM]];
            }
        }
        if ([self isValuePresent:reqParams[ID_TOKEN_HINT_PARAM]] && ![reqParams[ID_TOKEN_HINT_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", ID_TOKEN_HINT_PARAM]];
        }
        if ([self isValuePresent:reqParams[STATE_PARAM]] && ![reqParams[STATE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", STATE_PARAM]];
        }
        if ([self isValuePresent:reqParams[ADDITIONAL_PARAMETERS_PARAM]] && ![reqParams[ADDITIONAL_PARAMETERS_PARAM] isKindOfClass:[NSDictionary class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a JS object", ADDITIONAL_PARAMETERS_PARAM]];
        }
    }

    *errors = validationErrors;
    return validationErrors.count == 0;
}

-(OIDEndSessionRequest *)endSessionRequestForJSParams:(NSDictionary *)reqParams {
    NSDictionary *configParams = reqParams[CONFIGURATION_PARAM];
    NSURL *endSessionEndpoint = [NSURL URLWithString:configParams[CONFIGURATION_END_SESSION_ENDPOINT_PARAM]];
    // As w/ -authorizationRequestForJSParams:, we sillily set both authorizationEndpoint and tokenEndpoint
    // to our endSessionEndpoint, even though that's blatantly wrong, just so we can pass a non-nil NSURL
    // that we know won't actually get accessed in the course of doing the end session request.
    OIDServiceConfiguration *config =
        [[OIDServiceConfiguration alloc] initWithAuthorizationEndpoint:endSessionEndpoint
                                                         tokenEndpoint:endSessionEndpoint
                                                                issuer:nil
                                                  registrationEndpoint:nil
                                                    endSessionEndpoint:endSessionEndpoint];
    // Ditto -authorizationRequestForJSParams on letting calling code specify state and otherwise
    // falling back to randomly-generated state. An extra wrinkle is that OIDEndSessionRequest
    // doesn't expose its +generateState method in its header like OIDAuthorizationRequest does.
    // So we use OIDAuthorizationRequest's implementation, which is identical. See
    // https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuthCore/OIDAuthorizationRequest.m vs
    // https://github.com/openid/AppAuth-iOS/blob/master/Source/AppAuthCore/OIDEndSessionRequest.m
    NSString *state = [self coerceNSNullToNil:reqParams[STATE_PARAM]] ?: [OIDAuthorizationRequest generateState];
    return [[OIDEndSessionRequest alloc] initWithConfiguration:config
                                                   idTokenHint:[self coerceNSNullToNil:reqParams[ID_TOKEN_HINT_PARAM]]
                                         postLogoutRedirectURL:[NSURL URLWithString:[self coerceNSNullToNil:reqParams[POST_LOGOUT_REDIRECT_URL_PARAM]]]
                                                         state:state
                                          additionalParameters:[self preprocessEndSessionRequestAdditionalParams:reqParams[ADDITIONAL_PARAMETERS_PARAM]]];
}

// Pre-process additional parameters so that regardless of AppAuth behavior, we'll
// enforce the behavior that known parameters must be set via the documented
// params rather than additionalParameters param.
-(NSDictionary<NSString *, NSString *> *)preprocessEndSessionRequestAdditionalParams:(NSDictionary<NSString *, NSString *> *)params {
    static NSString * const BLACKLISTED[] = {
        @"id_token_hint",
        @"post_logout_redirect_uri",
        @"state"
    };

    static int BLACKLISTED_LENGTH = sizeof(BLACKLISTED) / sizeof(BLACKLISTED[0]);

    if ([self isValuePresent:params]) {
        NSMutableDictionary *processed = [[NSMutableDictionary alloc] initWithDictionary:params];
        for (int i = 0; i < BLACKLISTED_LENGTH; i++) {
            [processed removeObjectForKey:BLACKLISTED[i]];
        }
        return processed;
    } else {
        return nil;
    }
}

-(NSDictionary *)jsonForEndSessionResponse:(OIDEndSessionResponse *)response {
    if (!response) return nil;
    return @{
        @"request":                    [self jsonForNilable:[self jsonForReturnedEndSessionRequest:response.request]],
        @"state":                      [self jsonForNilable:response.state],
        @"additionalParameters":       [self jsonForNilable:response.additionalParameters]
    };
}

// As for authorization requests, we return the request back to JS. This is really just about being
// consistent w/ the pattern for authorization requests. The only potentially interesting piece of
// data that we generate on the native side for end session requests is the state param. But that's
// already included as a response field, and AppAuth already validates that the request and response
// state fields match before passing us the response. So there's nothing interesting calling code
// could do w/ this request.
-(NSDictionary *)jsonForReturnedEndSessionRequest:(OIDEndSessionRequest *)request {
    if (!request) return nil;
    return @{
        // Don't pass back the configuration. Nothing interesting can happen to it.
        @"postLogoutRedirectUrl":          [self jsonForNilable:request.postLogoutRedirectURL.absoluteString],
        @"idTokenHint":                    [self jsonForNilable:request.idTokenHint],
        @"state":                          [self jsonForNilable:request.state],
        @"additionalParameters":           [self jsonForNilable:request.additionalParameters]
    };
}

-(NSDictionary *)jsonForEndSessionError:(NSError *)error {
    if ([error.domain isEqualToString:OIDOAuthAuthorizationErrorDomain]) {
        if (error.code == OIDErrorCodeOAuthAuthorizationClientError) {
            // Ditto -jsonForNonErrorResponseAuthorizationError: on OIDErrorCodeOAuthAuthorizationClientError
            // really meaning INVALID_RESPONSE.
            return [self standardJSONForError:error type:INVALID_RESPONSE];
        }
    } else if ([error.domain isEqualToString:OIDGeneralErrorDomain]) {
        if (error.code == OIDErrorCodeNetworkError) {
            return [self standardJSONForError:error type:HTTP_ERROR];
        } else if (error.code == OIDErrorCodeUserCanceledAuthorizationFlow) {
            return [self standardJSONForError:error type:USER_CANCELLED];
        }
    }

    return [self standardJSONForError:error type:UNEXPECTED_ERROR];
}


// Utilities common to all request types

-(BOOL)isValuePresent:(id)param {
    return param ? param != [NSNull null] : NO;
}

-(id)coerceNSNullToNil:(id)val {
    return val == [NSNull null] ? nil : val;
}

-(void)launchAuthorizationFlowForCommand:(CDVInvokedUrlCommand *)command
                                    flow:(id<OIDExternalUserAgentSession> (^)()) flow {
    // Bail if an authorization flow is already in progress
    if (currentAuthorizationFlow) {
        NSDictionary *json = [self jsonForAuthorizationFlowAlreadyInProgress];
        CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }

    // Now jump back to the main thread to present the authorization flow UI. This avoids warnings
    // from the Main Thread Checker about performing UI updates on a background thread.
    dispatch_async(dispatch_get_main_queue(), ^{
        // Lock to avoid races initiating a new authorization flow
        @synchronized (self) {
            // Re-check that we're the only authorization flow now that we're in the synchronized section
            if (currentAuthorizationFlow) {
                NSDictionary *json = [self jsonForAuthorizationFlowAlreadyInProgress];
                CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
                [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
                return;
            }

            currentAuthorizationFlow = flow();
        }
    });
}

-(NSDictionary *)jsonForRequestValidationErrors:(NSArray<NSString *> *)validationErrors {
    NSString *message = [@"Request contained the following validation errors: " stringByAppendingString:[validationErrors componentsJoinedByString:@", "]];
    return @{
        @"type":         UNSENDABLE_REQUEST,
        @"message":      message,
        @"details":      message
    };
}

-(NSDictionary *)jsonForAuthorizationFlowAlreadyInProgress {
    return @{
        @"type":         UNSENDABLE_REQUEST,
        @"message":      @"Cannot send this request b/c another authorization flow is already in progress.",
        @"details":      @"Cannot send this request b/c another authorization flow is already in progress."
    };
}

-(NSDictionary *)standardJSONForError:(NSError *)error
                                 type:(NSString *)type {
    return @{
        @"type":         type,
        @"message":      error.localizedDescription,
        @"details":      error.localizedFailureReason ?: error.localizedDescription
    };
}

// to pass dates to JS, we send milliseconds since 1970, since that is what the Javascript Date constructor expects
-(id)jsonForDate:(NSDate *)date {
    return date ? [NSNumber numberWithDouble:([date timeIntervalSince1970] * 1000)] : [NSNull null];
}

// Coerce nil to NSNull for inserting into NSDictionary and NSArray.
// Note that we won't call this before using Cordova's +CDVPluginResult::resultWithStatus:messageAsDictionary
// method -- it already does its own handling for nil, so we'll pass in nil as is.
-(id)jsonForNilable:(id)nilable {
    return nilable ?: [NSNull null];
}

-(id)maybeString:(NSObject *)obj {
    return [self isValuePresent:obj] ? [obj isKindOfClass:[NSString class]] ? (NSString *)obj : obj.description : [NSNull null];
}

@end

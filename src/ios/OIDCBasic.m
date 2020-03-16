#import <objc/runtime.h>
#import <AppAuth/AppAuth.h>
#import "AppDelegate.h"
#import "OIDCBasic.h"

// Params from JS
static NSString * CONFIGURATION_PARAM = @"configuration";
static NSString * CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM = @"authorizationEndpoint";
static NSString * CLIENT_ID_PARAM = @"clientID";
static NSString * CLIENT_SECRET_PARAM = @"clientSecret";
static NSString * SCOPE_PARAM = @"scope";
static NSString * STATE_PARAM = @"state";
static NSString * REDIRECT_URL_PARAM = @"redirectURL";
static NSString * RESPONSE_TYPE_PARAM = @"responseType";
static NSString * ADDITIONAL_PARAMETERS_PARAM = @"additionalParameters";

// Error types
static NSString * UNSENDABLE_REQUEST = @"OIDC_UNSENDABLE_REQUEST";
static NSString * ERROR_RESPONSE = @"OIDC_ERROR_RESPONSE";
static NSString * INVALID_RESPONSE = @"OIDC_INVALID_RESPONSE";
static NSString * HTTP_ERROR = @"OIDC_HTTP_ERROR";
static NSString * USER_CANCELLED = @"OIDC_USER_CANCELLED";
static NSString * UNEXPECTED_ERROR = @"OIDC_UNEXPECTED_ERROR";

static id<OIDExternalUserAgentSession> currentAuthorizationFlow = nil;

// Have to register to handle redirections. See https://github.com/openid/AppAuth-iOS#authorizing-ios
// Use method swizzling to respect any existing application:openURL:options: implementation.
@implementation AppDelegate (OIDCBasicAppDelegate)

-(BOOL)oidcBasicApplication:(UIApplication *)app
                    openURL:(NSURL *)url
                    options:(NSDictionary<NSString *, id> *)options {
    if ([currentAuthorizationFlow resumeExternalUserAgentFlowWithURL:url]) {
        currentAuthorizationFlow = nil;
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

-(void)presentAuthorizationRequest:(CDVInvokedUrlCommand *)command {
    [self.commandDelegate runInBackground:^{
        NSDictionary * reqParams = [command argumentAtIndex:0 withDefault:nil andClass:[NSDictionary class]];

        NSMutableArray<NSString *> *validationErrors;
        if (![self validateAuthorizationRequestParams:reqParams errors:&validationErrors]) {
            NSDictionary *json = [self jsonForInvalidAuthorizationRequest:validationErrors];
            CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
            return;
        }

        OIDAuthorizationRequest *request = [self authorizationRequestForJSParams:reqParams];
        OIDAuthorizationCallback callback = ^(OIDAuthorizationResponse *response, NSError *error) {
            CDVPluginResult *result;
            if (response) {
                NSDictionary *json = [self jsonForSuccessfulAuthorizationResponse:response];
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:json];
            } else {
                NSDictionary *json = [self jsonForAuthorizationError:error];
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
            }
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        };

        @synchronized (self) {
            if (currentAuthorizationFlow) {
                NSDictionary *json = [self jsonForAuthorizationFlowAlreadyInProgress];
                CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:json];
                [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
                return;
            }

            // Initiate the authorizationRequest. NOTE: We call OIDAuthorizationService's
            // presentAuthorizationRequest:etc directly rather than using OIDAuthState's
            // authStateByPresentingAuthorizationRequest:etc helper as OIDAuthState assumes the entire
            // flow should be run on device, including the token exchange. Whereas the goal of this plugin
            // is just to expose the authorization request piece of the flow. We may later add a separate
            // method for performing the token exchange on device.
            currentAuthorizationFlow =
                [OIDAuthorizationService presentAuthorizationRequest:request
                                            presentingViewController:self.viewController
                                                            callback:callback];
        }
    }];
}

-(BOOL)validateAuthorizationRequestParams:reqParams
                               errors:(NSMutableArray<NSString *> **)errors {
    NSMutableArray<NSString *> *validationErrors = [[NSMutableArray alloc] init];

    if (!reqParams) {
        [validationErrors addObject:@"request params object is required"];
    } else {
        if (!reqParams[CONFIGURATION_PARAM]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param is required", CONFIGURATION_PARAM]];
        } else {
            if (![reqParams[CONFIGURATION_PARAM] isKindOfClass:[NSDictionary class]]) {
                [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a JS object", CONFIGURATION_PARAM]];
            } else {
                NSDictionary *configParams = reqParams[CONFIGURATION_PARAM];
                if (!configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param is required", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
                } else if (![configParams[CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM] isKindOfClass:[NSString class]]) {
                    [validationErrors addObject:[NSString stringWithFormat:@"%@.%@ param must be a string", CONFIGURATION_PARAM, CONFIGURATION_AUTHORIZATION_ENDPOINT_PARAM]];
                }
            }
        }
        if (reqParams[STATE_PARAM] && ![reqParams[STATE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", STATE_PARAM]];
        }
        if (reqParams[CLIENT_ID_PARAM] && ![reqParams[CLIENT_ID_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", CLIENT_ID_PARAM]];
        }
        if (reqParams[CLIENT_SECRET_PARAM] && ![reqParams[CLIENT_SECRET_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", CLIENT_SECRET_PARAM]];
        }
        if (reqParams[REDIRECT_URL_PARAM] && ![reqParams[REDIRECT_URL_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", REDIRECT_URL_PARAM]];
        }
        if (reqParams[REDIRECT_URL_PARAM] && ![reqParams[REDIRECT_URL_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", REDIRECT_URL_PARAM]];
        }
        if (reqParams[RESPONSE_TYPE_PARAM] && ![reqParams[RESPONSE_TYPE_PARAM] isKindOfClass:[NSString class]]) {
            [validationErrors addObject:[NSString stringWithFormat:@"%@ param must be a string", REDIRECT_URL_PARAM]];
        }
        if (reqParams[ADDITIONAL_PARAMETERS_PARAM] && ![reqParams[ADDITIONAL_PARAMETERS_PARAM] isKindOfClass:[NSDictionary class]]) {
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
    // initalizer does. See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDAuthorizationRequest.m
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
    NSString *state = reqParams[STATE_PARAM] ?: [OIDAuthorizationRequest generateState];
    return [[OIDAuthorizationRequest alloc] initWithConfiguration:config
                                                         clientId:reqParams[CLIENT_ID_PARAM]
                                                     clientSecret:reqParams[CLIENT_SECRET_PARAM]
                                                            scope:reqParams[SCOPE_PARAM]
                                                      redirectURL:[NSURL URLWithString:reqParams[REDIRECT_URL_PARAM]]
                                                     responseType:reqParams[RESPONSE_TYPE_PARAM]
                                                            state:state
                                                            nonce:nonce
                                                     codeVerifier:codeVerifier
                                                    codeChallenge:codeChallenge
                                              codeChallengeMethod:OIDOAuthorizationRequestCodeChallengeMethodS256
                                             additionalParameters:reqParams[ADDITIONAL_PARAMETERS_PARAM]];
}

-(NSDictionary *)jsonForInvalidAuthorizationRequest:(NSMutableArray<NSString *> *)validationErrors {
    NSString *message = [@"Request contained the following validation errors: " stringByAppendingString:[validationErrors componentsJoinedByString:@", "]];
    return @{
        @"type":         UNSENDABLE_REQUEST,
        @"message":      message,
        @"details":      message
    };
}

-(NSDictionary *)jsonForSuccessfulAuthorizationResponse:(OIDAuthorizationResponse *)response {
    if (!response) return nil;
    return @{
        @"request":                      [self jsonForNilable:[self jsonForReturnedRequest:response.request]],
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
-(NSDictionary *)jsonForReturnedRequest:(OIDAuthorizationRequest *)request {
    if (!request) return nil;
    return @{
        // Don't pass back the configuration. Nothing interesting can happen to it.
        @"responseType":               [self jsonForNilable:request.responseType],
        @"clientId":                   [self jsonForNilable:request.clientID],
        @"clientSecret":               [self jsonForNilable:request.clientSecret],
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

-(NSDictionary *)jsonForAuthorizationError:(NSError *)error {
    if ([error.domain isEqualToString:OIDOAuthAuthorizationErrorDomain]) {
        if (error.userInfo[OIDOAuthErrorResponseErrorKey]) {
            NSDictionary *respJson = [self jsonForFailedAuthorizationResponse:error.userInfo[OIDOAuthErrorResponseErrorKey]];
            return @{
                @"type":         ERROR_RESPONSE,
                @"message":      respJson[@"error"],
                @"details":      respJson[@"errorDescription"],
                @"response":     respJson
            };
        } else if (error.code == OIDErrorCodeOAuthAuthorizationClientError) {
            // The OIDErrorCodeOAuthAuthorizationClientError constant seems misleading to me.
            // AppAuth returns this error when the response doesn't meet our expectations, meaning
            // the PROVIDER did something not in keeping w/ our understanding of OIDC (or that
            // a malicious party tried to modify the provider's response). Either way call that
            // an INVALID_RESPONSE.
            return @{
                @"type":         INVALID_RESPONSE,
                @"message":      error.localizedDescription,
                @"details":      error.localizedFailureReason ?: error.localizedDescription
            };
        }
    } else if ([error.domain isEqualToString:OIDGeneralErrorDomain]) {
        if (error.code == OIDErrorCodeNetworkError) {
            return @{
                @"type":         HTTP_ERROR,
                @"message":      error.localizedDescription,
                @"details":      error.localizedFailureReason ?: error.localizedDescription
            };
        } else if (error.code == OIDErrorCodeUserCanceledAuthorizationFlow) {
            return @{
                @"type":         USER_CANCELLED,
                @"message":      error.localizedDescription,
                @"details":      error.localizedFailureReason ?: error.localizedDescription
            };
        }
    }

    return @{
        @"type":         UNEXPECTED_ERROR,
        @"message":      error.localizedDescription,
        @"details":      error.localizedFailureReason ?: error.localizedDescription
    };
}

-(NSDictionary *)jsonForFailedAuthorizationResponse:(NSDictionary *)response {
    if (!response) return nil;
    return @{
        @"error":                 [self maybeString:response[OIDOAuthErrorFieldError]],
        @"errorDescription":      [self maybeString:response[OIDOAuthErrorFieldErrorDescription]],
        @"errorUrl":              [self maybeString:response[OIDOAuthErrorFieldErrorURI]],
        @"state":                 [self maybeString:response[@"state"]]
    };
}

-(NSDictionary *)jsonForAuthorizationFlowAlreadyInProgress {
    return @{
        @"type":         UNSENDABLE_REQUEST,
        @"message":      @"Cannot send this authorization request b/c another authorization flow is already in progress.",
        @"details":      @"Cannot send this authorization request b/c another authorization flow is already in progress."
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
    return obj ? [obj isKindOfClass:[NSString class]] ? (NSString *)obj : obj.description : [NSNull null];
}

@end

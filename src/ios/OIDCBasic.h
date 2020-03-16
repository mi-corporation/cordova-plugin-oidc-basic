#import <Cordova/CDVPlugin.h>

@interface OIDCBasic : CDVPlugin

-(void)presentAuthorizationRequest:(CDVInvokedUrlCommand *)command;

@end

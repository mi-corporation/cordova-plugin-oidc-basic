using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

using IdentityModel;
using IdentityModel.OidcClient;

namespace OIDCBasicRuntimeComponent
{
    public sealed class AuthorizationRequestParams
    {
        public AuthorizationServiceConfiguration Configuration { get; set; }
        public string ClientId { get; set; }
        public string Scope { get; set; }
        public Uri RedirectUrl { get; set; }
        public string ResponseType { get; set; }
        public string State { get; set; }
        public IDictionary<string, string> AdditionalParameters { get; set; }

        /// <summary>
        /// Generate an <see cref="AuthorizationRequest"/> for these <see cref="AuthorizationRequestParams"/>.
        /// Note that repeated <see cref="GenerateRequestAsync"/> calls will generate distinct
        /// requests b/c nonce, PKCE params, and possibly state will be regenerated each time.
        /// </summary>
        public Windows.Foundation.IAsyncOperation<AuthorizationRequest> GenerateRequestAsync() {
            return GenerateRequestInner().AsAsyncOperation();
        }

        private async Task<AuthorizationRequest> GenerateRequestInner() {
            // Use IdentityModel.OidcClient to generate the URL. Most of all, this lets us use their code for
            // generating nonce, state, and PKCE params.
            // Don't do much validation here, b/c we'll let IdentityModel.OidcClient handle that.
            // But DO validate that Configuration is non-null, to avoid a NPE.
            if (Configuration == null) throw new InvalidOperationException($"{nameof(Configuration)} is required");
            var options = new OidcClientOptions {
                ProviderInformation = {
                    AuthorizeEndpoint = Configuration.AuthorizationEndpoint?.AbsoluteUri
                },
                ClientId = ClientId,
                Scope = Scope,
                RedirectUri = RedirectUrl?.AbsoluteUri
            };
            var extraParams = GetOidcClientExtraParameters();
            var authState = await new OidcClient(options).PrepareLoginAsync(extraParams);
            return RecoverAuthorizationRequest(authState, extraParams);
        }

        private static readonly string[] BLACKLISTED_PARAMS = new[] {
            OidcConstants.AuthorizeRequest.Scope,
            OidcConstants.AuthorizeRequest.ResponseType,
            OidcConstants.AuthorizeRequest.ClientId,
            OidcConstants.AuthorizeRequest.RedirectUri,
            OidcConstants.AuthorizeRequest.State,
            OidcConstants.AuthorizeRequest.Nonce,
            OidcConstants.AuthorizeRequest.CodeChallenge,
            OidcConstants.AuthorizeRequest.CodeChallengeMethod
        };

        private Dictionary<string, string> GetOidcClientExtraParameters() {
            var extraParams = AdditionalParameters == null ? new Dictionary<string, string>() : new Dictionary<string, string>(AdditionalParameters);

            // Apply blacklist to extraParameters dictionary so that we enforce the behavior that known parameters must be set
            // via the documented params rather than the additionalParameters param.
            foreach (var blacklisted in BLACKLISTED_PARAMS) extraParams.Remove(blacklisted);

            return extraParams;
        }

        private AuthorizationRequest RecoverAuthorizationRequest(AuthorizeState authState, Dictionary<string, string> extraParams) {
            // We'll post-process the StartUrl from IdentityModel.OidcClient, both so we can parse out request fields that
            // IdentityModel.OidcClient generates but doesn't expose in any form except in the StartUrl, and so we can modify
            // a couple of request fields that IdentityModel.OidcClient doesn't expose explicit config properties for.
            var uriBuilder = new UriBuilder(authState.StartUrl);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            // Apply overrides.
            // ResponseType -- IdentityModel.OidcClient hard-codes to code. We'll be more permissive.
            if (ResponseType != null) query.Set(OidcConstants.AuthorizeRequest.ResponseType, ResponseType);
            // State -- IdentityModel.OidcClient always generates random state, but we'll let calling code override.
            // This is needed to support the use case of calling code encoding current UI state or other info in the state
            // param. But it also means calling code has the responsibility for using the state param correctly. In particular,
            // the spec says that clients SHOULD make their state param opaque and non-guessable.
            // See https://tools.ietf.org/html/rfc6749#section-10.12.
            // (For what it's worth, I think that section applies more closely to web apps and that for native apps PKCE
            // defends against the same attacks in a more robust way. But I'd still recommend calling code make their state
            // opaque and non-guessable as an extra security measure.)
            if (State != null) query.Set(OidcConstants.AuthorizeRequest.State, State);

            uriBuilder.Query = query.ToString();

            return new AuthorizationRequest {
                ClientId = ClientId,
                Scope = Scope,
                RedirectUrl = RedirectUrl,
                // Exposed only via query string
                ResponseType = query.Get(OidcConstants.AuthorizeRequest.ResponseType),
                // Exposed via AuthorizeState.State, but we'll read from query string to pick up our potential override
                State = query.Get(OidcConstants.AuthorizeRequest.State),
                Nonce = authState.Nonce,
                CodeVerifier = authState.CodeVerifier,
                // Exposed only via query string
                CodeChallenge = query.Get(OidcConstants.AuthorizeRequest.CodeChallenge),
                // Exposed only via query string
                CodeChallengeMethod = query.Get(OidcConstants.AuthorizeRequest.CodeChallengeMethod),
                AdditionalParameters = extraParams,
                RequestUrl = uriBuilder.Uri
            };
        }
    }
}

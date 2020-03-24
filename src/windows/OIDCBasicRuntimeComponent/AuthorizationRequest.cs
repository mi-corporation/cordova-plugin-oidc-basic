using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using IdentityModel.OidcClient;

namespace OIDCBasicRuntimeComponent
{
    public sealed class AuthorizationRequest
    {
        public string ClientId { get; set; }
        public string Scope { get; set; }
        public Uri RedirectUrl { get; set; }
        public string ResponseType { get; set; }
        public string State { get; set; }
        public string Nonce { get; set; }
        public string CodeVerifier { get; set; }
        public string CodeChallenge { get; set; }
        public string CodeChallengeMethod { get; set; }
        public IDictionary<string, string> AdditionalParameters { get; set; }
        public Uri RequestUrl { get; set; }
    }
}

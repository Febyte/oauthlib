using System;
using System.Net.Http;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace MyHealthDocsClientLib
{
    public abstract class TokenClient
    {
        public string TokenEndpointUri { get; protected set; }

        protected static string BuildHeaderAndPayload(string clientId, string tokenEndpointUri)
        {
            IDictionary<string, string> header = new Dictionary<string, string>()
            {
                { "alg", "RS256" },
                { "typ", "JWT" },
            };

            string headerText = JsonSerializer.Serialize(header);
            string headerEncoded = Base64UrlEncoder.Encode(headerText);

            DateTime now = DateTime.UtcNow;
            DateTime epoch = new DateTime(1970, 01, 01);

            int notBefore = Convert.ToInt32((now.AddMinutes(-5) - epoch).TotalSeconds);
            int expiresAt = Convert.ToInt32((now.AddMinutes(5) - epoch).TotalSeconds);

            IDictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "sub", clientId },
                { "jti", Guid.NewGuid() },
                { "nbf", notBefore },
                { "exp", expiresAt },
                { "iss", clientId },
                { "aud", tokenEndpointUri },
            };

            string payloadText = JsonSerializer.Serialize(payload);
            string payloadEncoded = Base64UrlEncoder.Encode(payloadText);

            string signaturePayloadText = $"{headerEncoded}.{payloadEncoded}";
            return signaturePayloadText;
        }

        public abstract Task<string> BuildClientAssertation(string clientId);

        public abstract Task<Token> GetAccessToken(HttpClient httpClient, string clientId);

        public abstract Task<Token> ExchangeToken(HttpClient httpClient, Token initialToken, string requestedClientId, string requestedSubject);
    }
}

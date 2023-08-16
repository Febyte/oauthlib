using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Net.Http;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MyHealthDocsClientLib
{
    internal class TokenCertificateStoreClient : TokenClient
    {
        private readonly string _thumbprint;

        public TokenCertificateStoreClient(string tokenEndpointUri, string thumbprint)
        {
            TokenEndpointUri = tokenEndpointUri;
            _thumbprint = thumbprint;
        }

        public override Task<string> BuildClientAssertion(string clientId)
        {
            string signaturePayloadText = BuildHeaderAndPayload(clientId, TokenEndpointUri);
            byte[] signaturePayloadBytes = Encoding.UTF8.GetBytes(signaturePayloadText);

            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection findResults = my.Certificates.Find(X509FindType.FindByThumbprint, _thumbprint, false);
            X509Certificate2 cert = findResults[0];
            RSA key = cert.GetRSAPrivateKey();
            byte[] signatureBytes = key.SignData(signaturePayloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            string signatureEncoded = Base64UrlEncoder.Encode(signatureBytes);

            string jwt = $"{signaturePayloadText}.{signatureEncoded}";
            return Task.FromResult(jwt);
        }

        public override Task<Token> ExchangeToken(HttpClient httpClient, Token initialToken, string requestedClientId, string requestedSubject)
        {
            throw new NotImplementedException();
        }

        public override async Task<Token> GetAccessToken(HttpClient httpClient, string clientId)
        {
            string clientAssertion = await BuildClientAssertion(clientId);

            FormUrlEncodedContent payload = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "grant_type", "client_credentials" },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", clientAssertion },
            });

            HttpResponseMessage response = await httpClient.PostAsync(TokenEndpointUri, payload);
            if (response.IsSuccessStatusCode)
            {
                Token token = await JsonSerializer.DeserializeAsync<Token>(await response.Content.ReadAsStreamAsync());
                return token;
            }
            else
            {
                throw new Exception($"Error fetching management token ({response.StatusCode}): {await response.Content.ReadAsStringAsync()}");
            }
        }
    }
}

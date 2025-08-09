using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;
using System.Net.Http;
using System.Collections.Generic;
using System.Text.Json;

namespace MyHealthDocsClientLib
{
    public class TokenKeyVaultClient : TokenClient
    {
        private readonly string _keyVaultUri;
        private readonly string _keyName;
        private readonly string _tenantId;

        public TokenKeyVaultClient(string tokenEndpointUri, string keyVaultUri, string keyName, string tenantId)
        {
            TokenEndpointUri = tokenEndpointUri;
            _keyVaultUri = keyVaultUri;
            _keyName = keyName;
            _tenantId = tenantId;
        }

        public override async Task<string> BuildClientAssertion(string clientId)
        {
            string signaturePayloadText = BuildHeaderAndPayload(clientId, TokenEndpointUri);
            byte[] signaturePayloadBytes = Encoding.UTF8.GetBytes(signaturePayloadText);

            KeyClient client = new KeyClient(new Uri(_keyVaultUri), new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeAzureCliCredential = true,
                ExcludeAzureDeveloperCliCredential = true,
                ExcludeEnvironmentCredential = true,
                ExcludeInteractiveBrowserCredential = true,
                ExcludeSharedTokenCacheCredential = true,
                ExcludeVisualStudioCredential = true,
                ExcludeWorkloadIdentityCredential = true,

                //ExcludeManagedIdentityCredential = true,
                TenantId = _tenantId,
            }));
            CryptographyClient cryptoClient = client.GetCryptographyClient(_keyName);

            using (SHA256 hash = SHA256.Create())
            {
                byte[] signaturePayloadDigest = hash.ComputeHash(signaturePayloadBytes);
                SignResult signResult = await cryptoClient.SignAsync(SignatureAlgorithm.RS256, signaturePayloadDigest);
                byte[] signatureBytes = signResult.Signature;
                string signatureEncoded = Base64UrlEncoder.Encode(signatureBytes);

                string jwt = $"{signaturePayloadText}.{signatureEncoded}";
                return jwt;
            }
        }

        public override async Task<Token> ExchangeToken(HttpClient httpClient, Token initialToken, string requestedClientId, string requestedSubject)
        {
            string clientAssertion = await BuildClientAssertion(requestedClientId);

            FormUrlEncodedContent payload = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "scope", "openid" },
                { "subject_token", initialToken.AccessToken },
                { "requested_subject", requestedSubject },
                { "client_id", requestedClientId },
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

using Azure.Core;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace KeyVaultYouTubeDemo
{
    public static class KeyVaultExtensions
    {
        public static WebApplicationBuilder AddKeyVaultConfiguration(this WebApplicationBuilder builder)
        {
            // Only enable KeyVault in production and if the KeyVault is enabled in the configuration
            if (!builder.Environment.IsProduction() || builder.Configuration["KeyVault:enabled"] != bool.TrueString)
            {
                return builder;
            }

            var keyVaultUri = new Uri(builder.Configuration["KeyVault:url"] ?? throw new InvalidOperationException("KeyVault URL must be provided."));
            TokenCredential credential;

            var credentialType = builder.Configuration["KeyVault:credentialType"] switch
            {
                nameof(CredentialType.ManagedIdentity) => CredentialType.ManagedIdentity,
                nameof(CredentialType.ServicePrincipal) => CredentialType.ServicePrincipal,
                _ => throw new InvalidOperationException("Invalid Credential Type")
            };

            switch (credentialType)
            {
                case CredentialType.ManagedIdentity:
                    credential = new DefaultAzureCredential();
                    break;
                case CredentialType.ServicePrincipal:
                    var tenantId = builder.Configuration["KeyVault:tenantId"] ?? throw new InvalidOperationException("TenantId must be provided for Service Principal.");
                    var clientId = builder.Configuration["KeyVault:clientId"] ?? throw new InvalidOperationException("ClientId must be provided for Service Principal.");
                    var clientSecret = builder.Configuration["KeyVault:clientSecret"] ?? throw new InvalidOperationException("ClientSecret must be provided for Service Principal.");
                    credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
                    break;
                default:
                    throw new InvalidOperationException("Invalid Credential Type");
            }

            builder.Configuration.AddAzureKeyVault(
                keyVaultUri,
                credential,
                new AzureKeyVaultConfigurationOptions
                {
                    Manager = new CustomSecretManager("KeyVaultDemo"),
                    ReloadInterval = TimeSpan.FromSeconds(30)
                });

            return builder;
        }

        private enum CredentialType
        {
            /// <summary>
            /// Managed Identity will be used to authenticate to the KeyVault, using the DefaultAzureCredential
            /// </summary>
            ManagedIdentity,

            /// <summary>
            /// Service Principal will be used to authenticate to the KeyVault, using the ClientSecretCredential
            /// ClientId, ClientSecret, and TenantId must be provided in the configuration
            /// </summary>
            ServicePrincipal
        }
    }

    // CustomSecretManager implementation
    public class CustomSecretManager : KeyVaultSecretManager
    {
        private readonly string _prefix;

        public CustomSecretManager(string prefix)
        {
            _prefix = prefix;
        }

        public override bool Load(SecretProperties secret)
        {
            // Load all secrets
            return true;
        }

        public override string GetKey(KeyVaultSecret secret)
        {
            // Remove the prefix from the secret name
            return secret.Name.StartsWith(_prefix) ? secret.Name.Substring(_prefix.Length) : secret.Name;
        }
    }
}

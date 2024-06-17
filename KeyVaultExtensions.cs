using Azure.Core;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;

namespace KeyVaultYouTubeDemo;

public static class KeyVaultExtensions
{
    public static WebApplicationBuilder AddKeyVaultConfiguration(this WebApplicationBuilder builder)
    {
        // Only enable KeyVault in production and if the KeyVault is enabled in the configuration
        if (!builder.Environment.IsProduction() || builder.Configuration["KeyVault:enabled"] != bool.TrueString) return builder;

        var keyVaultUri = new Uri(builder.Configuration["KeyVault:url"]!);
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
                var tenantId = builder.Configuration["KeyVault:tenantId"]!;
                var clientId = builder.Configuration["KeyVault:clientId"]!;
                var clientSecret = builder.Configuration["KeyVault:clientSecret"]!;
                credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
                break;
            default:
                throw new InvalidOperationException("Invalid Credential Type");
        }
    
        builder.Configuration.AddAzureKeyVault(
            keyVaultUri,
            credential,
            new AzureKeyVaultConfigurationOptions()
            {
                Manager = new CustomSecretManager("KeyVaultDemo"),
                ReloadInterval = TimeSpan.FromSeconds(30)
            }
        );

        return builder;
    }
    
    enum CredentialType
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

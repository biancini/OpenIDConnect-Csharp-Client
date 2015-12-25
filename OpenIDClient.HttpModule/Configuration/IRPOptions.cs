namespace OpenIDClient.HttpModule.Configuration
{
    using System.IdentityModel.Configuration;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Root interface for the options objects, handling all configuration of
    /// AuthServices.
    /// </summary>
    public interface IRPOptions
    {
        /// <summary>
        /// Application root relative path for AuthServices endpoints. The
        /// default should be "/AuthServices".
        /// </summary>
        string ModulePath { get; }

        /// <summary>
        /// The System.IdentityModel configuration to use.
        /// </summary>
        IdentityConfiguration SystemIdentityModelIdentityConfiguration { get; }

        /// <summary>
        /// Certificate for service provider to use when signing assertions
        /// </summary>
        X509Certificate2 SignCertificate { get; set; }

        /// <summary>
        /// Certificate for service provider to use when crypting assertions
        /// </summary>
        X509Certificate2 EncCertificate { get; set; }
    }
}

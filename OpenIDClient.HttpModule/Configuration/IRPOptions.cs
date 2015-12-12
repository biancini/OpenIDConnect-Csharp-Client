namespace OpenIDClient.HttpModule.Configuration
{
    using System.IdentityModel.Configuration;

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
    }
}

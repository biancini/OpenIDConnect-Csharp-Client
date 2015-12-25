using System.Security.Cryptography;

namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// Options implementation for handling in memory options.
    /// </summary>
    public class Options : IOptions
    {
        /// <summary>
        /// Reads the options from the current config file.
        /// </summary>
        /// <returns>Options object.</returns>
        public static Options FromConfiguration
        {
            get
            {
                var options = new Options(OpenIDConfigurationSection.Current);
                if (OpenIDConfigurationSection.Current.SignCertificateConfiguration != null)
                {
                    options.rpOptions.SignCertificate = OpenIDConfigurationSection.Current.SignCertificateConfiguration.LoadCertificate();
                }
                if (OpenIDConfigurationSection.Current.EncCertificateConfiguration != null)
                {
                    options.rpOptions.EncCertificate = OpenIDConfigurationSection.Current.EncCertificateConfiguration.LoadCertificate();
                }

                OpenIDConfigurationSection.Current.OpenIDProviders.RegisterOpenIDProviders(options);
                return options;
            }
        }

        /// <summary>
        /// Creates an options object with the specified SPOptions.
        /// </summary>
        /// <param name="rpOptions"></param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "sp")]
        public Options(IRPOptions rpOptions)
        {
            this.rpOptions = rpOptions;
        }

        private readonly IRPOptions rpOptions;

        /// <summary>
        /// Options for the service provider's behaviour; i.e. everything except
        /// the idp and federation list.
        /// </summary>
        public IRPOptions RPOptions
        {
            get
            {
                return rpOptions;
            }
        }


        /// <summary>
        /// Creates an options object with the specified SPOptions.
        /// </summary>
        /// <param name="Options"></param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "sp")]
        public Options(OpenIDConfigurationSection Options)
        {
            rpOptions = Options;
        }

        private readonly OpenIDProviderDictionary openIDProviders = new OpenIDProviderDictionary();

        /// <summary>
        /// Available identity providers.
        /// </summary>
        public OpenIDProviderDictionary OpenIDProviders
        {
            get
            {
                return openIDProviders;
            }
        }
    }
}

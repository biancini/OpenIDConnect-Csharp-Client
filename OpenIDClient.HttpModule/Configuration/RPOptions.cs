namespace OpenIDClient.HttpModule.Configuration
{
    using System;
    using System.IdentityModel.Configuration;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Options for the service provider's behaviour; i.e. everything except
    /// the idp and federation list.
    /// </summary>
    public class RPOptions : IRPOptions
    {
        private string modulePath = "/OpenID";

        /// <summary>
        /// Application root relative path for AuthServices endpoints. The
        /// default is "/OpenID".
        /// </summary>
        public string ModulePath
        {
            get
            {
                return modulePath;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                value = value.TrimEnd('/');

                if (!value.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                {
                    value = "/" + value;
                }

                modulePath = value;
            }
        }

        private IdentityConfiguration systemIdentityModelIdentityConfiguration = new IdentityConfiguration(false);

        /// <summary>
        /// The System.IdentityModel configuration to use.
        /// </summary>
        public IdentityConfiguration SystemIdentityModelIdentityConfiguration
        {
            get
            {
                return systemIdentityModelIdentityConfiguration;
            }
        }

        /// <summary>
        /// Certificate for service provider to use when signing assertions
        /// </summary>
        public X509Certificate2 SignCertificate { get; set; }


        /// <summary>
        /// Certificate for service provider to use when crypting assertions
        /// </summary>
        public X509Certificate2 EncCertificate { get; set; }
    }
}

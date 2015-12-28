using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.Linq;
using System.IdentityModel.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics.CodeAnalysis;

namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// Config section for the module.
    /// </summary>
    public class OpenIDConfigurationSection : ConfigurationSection, IRPOptions
    {
        private static readonly OpenIDConfigurationSection current =
            (OpenIDConfigurationSection)ConfigurationManager.GetSection("openid.authServices");

        private bool allowChange = true;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1500:VariableNamesShouldNotMatchFieldNames", MessageId = "allowChange")]
        internal void AllowChange(bool allowChange)
        {
            this.allowChange = allowChange;
        }

        /// <summary>
        /// Used for testing, always returns true in production.
        /// </summary>
        /// <returns>Returns true (unless during tests)</returns>
        public override bool IsReadOnly()
        {
            return !allowChange;
        }

        /// <summary>
        /// Ctor
        /// </summary>
        public OpenIDConfigurationSection()
        {
        }

        const string modulePath = "modulePath";
        /// <summary>
        /// Application root relative path for AuthServices endpoints. The 
        /// default is "AuthServices".
        /// </summary>
        [ConfigurationProperty(modulePath, IsRequired = false, DefaultValue = "/OpenID")]
        [RegexStringValidator("/.*")]
        public string ModulePath
        {
            get
            {
                return (string)base[modulePath];
            }
        }

        /// <summary>
        /// Current config as read from app/web.config.
        /// </summary>
        public static OpenIDConfigurationSection Current
        {
            get
            {
                return current;
            }
        }

        const string openidProviders = "openidProviders";
        /// <summary>
        /// Set of openid providers known to the service provider.
        /// </summary>
        [ConfigurationProperty(openidProviders)]
        [ConfigurationCollection(typeof(OpenIDProviderElement))]
        public OpenIDProviderCollection OpenIDProviders
        {
            get
            {
                return (OpenIDProviderCollection)base[openidProviders];
            }
        }

        private IdentityConfiguration systemIdentityModelIdentityConfiguration = new IdentityConfiguration(true);

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
        /// Flag indicating wether to check SSL certificate or not
        /// </summary>
        [ConfigurationProperty("checkSslCertificate")]
        [ExcludeFromCodeCoverage]
        public bool CheckSslCertificateConfiguration
        {
            get
            {
                return (bool)base["checkSslCertificate"];
            }
            internal set
            {
                base["checkSslCertificate"] = value;
            }
        }

        /// <summary>
        /// Flag indicating wether to check SSL certificate or not
        /// </summary>
        public bool CheckSslCertificate { get; set; }

        /// <summary>
        /// Certificate location for the certificate the Service Provider uses to sign assertions.
        /// </summary>
        [ConfigurationProperty("signCertificate")]
        [ExcludeFromCodeCoverage]
        public CertificateElement SignCertificateConfiguration
        {
            get
            {
                return (CertificateElement)base["signCertificate"];
            }
            internal set
            {
                base["signCertificate"] = value;
            }
        }

        /// <summary>
        /// Certificate for service provider to use when signing assertions
        /// </summary>
        public X509Certificate2 SignCertificate { get; set; }

        /// <summary>
        /// Certificate location for the certificate the Service Provider uses to crypt assertions.
        /// </summary>
        [ConfigurationProperty("encCertificate")]
        [ExcludeFromCodeCoverage]
        public CertificateElement EncCertificateConfiguration
        {
            get
            {
                return (CertificateElement)base["encCertificate"];
            }
            internal set
            {
                base["encCertificate"] = value;
            }
        }

        /// <summary>
        /// Certificate for service provider to use when crypting assertions
        /// </summary>
        public X509Certificate2 EncCertificate { get; set; }
    }
}

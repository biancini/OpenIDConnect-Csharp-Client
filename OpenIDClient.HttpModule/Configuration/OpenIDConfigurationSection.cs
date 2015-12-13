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

        const string baseUrls = "baseUrls";
        /// <summary>
        /// Application root relative path for AuthServices endpoints. The 
        /// default is "AuthServices".
        /// </summary>
        [ConfigurationProperty(baseUrls, IsRequired = false)]
        public string BaseUrls
        {
            get
            {
                return (string)base[baseUrls];
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
    }
}

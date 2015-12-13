namespace OpenIDClient.HttpModule.Configuration
{
    using System.Configuration;
    using System.Collections.Generic;

    /// <summary>
    /// Config element for the identity provider element.
    /// </summary>
    public class OpenIDProviderElement : ConfigurationElement
    {
        private bool isReadOnly = true;

        internal void AllowConfigEdit(bool allow)
        {
            isReadOnly = !allow;
        }

        /// <summary>
        /// Allows local modification of the configuration for testing purposes
        /// </summary>
        /// <returns></returns>
        public override bool IsReadOnly()
        {
            return isReadOnly;
        }

        const string entityId = "entityId";
        /// <summary>
        /// EntityId as presented by the OP. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty(entityId, IsRequired = true)]
        public string EntityId
        {
            get
            {
                return (string)base[entityId];
            }
            internal set
            {
                base[entityId] = value;
            }
        }

        const string selfRegistration = "selfRegistration";
        /// <summary>
        /// The requested authentication context for the authentication request.
        /// </summary>
        [ConfigurationProperty(selfRegistration, IsRequired = true, DefaultValue = true)]
        public bool SelfRegistration
        {
            get
            {
                return (bool)base[selfRegistration];
            }
        }

        const string clientId = "clientId";
        /// <summary>
        /// The requested authentication context for the authentication request.
        /// </summary>
        [ConfigurationProperty(clientId, IsRequired = false)]
        public string ClientId
        {
            get
            {
                return (string)base[clientId];
            }
        }

        const string clientSecret = "clientSecret";
        /// <summary>
        /// The requested authentication context for the authentication request.
        /// </summary>
        [ConfigurationProperty(clientSecret, IsRequired = false)]
        public string ClientSecret
        {
            get
            {
                return (string)base[clientSecret];
            }
        }

        const string opIssuer = "opIssuer";
        /// <summary>
        /// The Issuer to be used to retrieve OP properties.
        /// </summary>
        [ConfigurationProperty(opIssuer, IsRequired = false)]
        public string OPIssuer
        {
            get
            {
                return (string)base[opIssuer];
            }
            internal set
            {
                base[opIssuer] = value;
            }
        }

        const string registrationEndpoint = "registrationEndpoint";
        /// <summary>
        /// The Issuer to be used to retrieve OP properties.
        /// </summary>
        [ConfigurationProperty(registrationEndpoint, IsRequired = false)]
        public string RegistrationEndpoint
        {
            get
            {
                return (string)base[registrationEndpoint];
            }
            internal set
            {
                base[registrationEndpoint] = value;
            }
        }

        const string authorizationEndpoint = "authorizationEndpoint";
        /// <summary>
        /// AuthorizationEndpoint as presented by the OP. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty(authorizationEndpoint, IsRequired = false)]
        public string AuthorizationEndpoint
        {
            get
            {
                return (string)base[authorizationEndpoint];
            }
            internal set
            {
                base[authorizationEndpoint] = value;
            }
        }

        const string tokenEndpoint = "tokenEndpoint";
        /// <summary>
        /// AuthorizationEndpoint as presented by the OP. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty(tokenEndpoint, IsRequired = false)]
        public string TokenEndpoint
        {
            get
            {
                return (string)base[tokenEndpoint];
            }
            internal set
            {
                base[tokenEndpoint] = value;
            }
        }

        const string userinfoEndpoint = "userinfoEndpoint";
        /// <summary>
        /// AuthorizationEndpoint as presented by the OP. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty(userinfoEndpoint, IsRequired = false)]
        public string UserinfoEndpoint
        {
            get
            {
                return (string)base[userinfoEndpoint];
            }
            internal set
            {
                base[userinfoEndpoint] = value;
            }
        }

        public string Description
        {
            get
            {
                string descr = "";
                if (SelfRegistration)
                {
                    descr = "client self registered";
                }
                else
                {
                    descr = "client NOT self registered";
                }
                return descr;
            }
        }
    }
}

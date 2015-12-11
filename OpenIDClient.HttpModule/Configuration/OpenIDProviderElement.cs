using System.Configuration;

namespace OpenIDClient.HttpModule.Configuration
{
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
        [ConfigurationProperty(selfRegistration, IsRequired = true)]
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

        const string authorizationEndpoint = "authorizationEndpoint";
        /// <summary>
        /// AuthorizationEndpoint as presented by the OP. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty(authorizationEndpoint, IsRequired = true)]
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
        [ConfigurationProperty(tokenEndpoint, IsRequired = true)]
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
        [ConfigurationProperty(userinfoEndpoint, IsRequired = true)]
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
    }
}

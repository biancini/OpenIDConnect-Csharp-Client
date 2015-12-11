namespace OpenIDClient.HttpModule.Configuration
{
    using System;

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
    }
}

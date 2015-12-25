using OpenIDClient.HttpModule.Configuration;
using System;

namespace OpenIDClient.HttpModule.WebSso
{
    /// <summary>
    /// The urls of AuthServices that are used in various messages.
    /// </summary>
    public class OpenIDUrls
    {
        /// <summary>
        /// Resolve the urls for AuthServices from an http request and options.
        /// </summary>
        /// <param name="spOptions">SP Options to get module path from.</param>
        /// <param name="request">Request to get application root url from.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2208:InstantiateArgumentExceptionsCorrectly"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "sp")]
        public OpenIDUrls(IRPOptions rpOptions, Uri baseUrl)
        {
            if (baseUrl == null)
            {
                throw new ArgumentNullException(nameof(baseUrl));
            }

            if (rpOptions == null)
            {
                throw new ArgumentNullException(nameof(rpOptions));
            }

            Init(rpOptions, baseUrl);
        }

        void Init(IRPOptions rpOptions, Uri baseUrl)
        {
            string modulePath = rpOptions.ModulePath;
            if (!modulePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("modulePath should start with /.");
            }

            ApplicationBase = baseUrl;
            var authServicesRoot = ApplicationBase.ToString().TrimEnd('/') + modulePath + "/";

            AuthenticateCommand = new Uri(authServicesRoot + CommandFactory.AuthenticateCommandName);
            CodeCallbackCommand = new Uri(authServicesRoot + CommandFactory.CodeCallbackCommandName);
            JwksCallbackCommand = new Uri(authServicesRoot + CommandFactory.JwksCallbackCommandName);
        }

        /// <summary>
        /// The abbplication base Url.
        /// </summary>
        public Uri ApplicationBase { get; private set; }

        /// <summary>
        /// The full url of the authentication command.
        /// </summary>
        public Uri AuthenticateCommand { get; private set; }

        /// <summary>
        /// The full url of the code callback command.
        /// </summary>
        public Uri CodeCallbackCommand { get; private set; }

        /// <summary>
        /// The full url of the JWKS callback command.
        /// </summary>
        public Uri JwksCallbackCommand { get; private set; }
    }
}
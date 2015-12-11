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
        /// <param name="request">Request to get application root url from.</param>
        /// <param name="spOptions">SP Options to get module path from.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2208:InstantiateArgumentExceptionsCorrectly"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "sp")]
        public OpenIDUrls(HttpRequestData request, IRPOptions rpOptions)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (rpOptions == null)
            {
                throw new ArgumentNullException(nameof(rpOptions));
            }

            Init(request.ApplicationUrl, rpOptions.ModulePath);
        }

        void Init(Uri applicationUrl, string modulePath)
        {
            if (!modulePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("modulePath should start with /.");
            }

            ApplicationBase = new Uri(applicationUrl.AbsoluteUri);
            var authServicesRoot = ApplicationBase.ToString().TrimEnd('/') + modulePath + "/";

            AuthenticateCommand = new Uri(authServicesRoot + CommandFactory.AuthenticateCommandName);
            CodeCallbackCommand = new Uri(authServicesRoot + CommandFactory.CodeCallbackCommandName);
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
    }
}
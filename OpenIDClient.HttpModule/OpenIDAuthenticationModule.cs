namespace OpenIDClient.HttpModule
{
    using System;
    using System.Web;
    using System.Diagnostics.CodeAnalysis;
    using OpenIDClient.HttpModule.WebSso;
    using OpenIDClient.HttpModule.Configuration;

    /// <summary>
    /// Http Module for SAML2 authentication. The module hijacks the 
    /// ~/Saml2AuthenticationModule/ path of the http application to provide 
    /// authentication services.
    /// </summary>
    // Not included in code coverage as the http module is tightly dependent on IIS.
    [ExcludeFromCodeCoverage]
    public class OpenIDAuthenticationModule : IHttpModule
    {
        /// <summary>
        /// Init the module and subscribe to events.
        /// </summary>
        /// <param name="context"></param>
        public void Init(HttpApplication context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.PostMapRequestHandler += new EventHandler(Application_PostMapRequestHandler);
        }

        private void Application_PostMapRequestHandler(object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;
            // swap the current handler
            app.Context.Handler = new OpenIDHttpHandler(app.Context.Handler);
        }

        /// <summary>
        /// IDisposable implementation.
        /// </summary>
        public virtual void Dispose()
        {
            // Deliberately do nothing, unsubscribing from events is not
            // needed by the IIS model. Trying to do so throws exceptions.
        }
      }
}
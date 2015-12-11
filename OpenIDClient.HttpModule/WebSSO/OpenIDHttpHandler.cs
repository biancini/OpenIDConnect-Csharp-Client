namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Net;
    using System.Web;
    using System.Web.SessionState;
    using OpenIDClient.HttpModule.Configuration;
    using OpenIDClient.HttpModule.WebSso;

    public class OpenIDHttpHandler : IHttpHandler, IRequiresSessionState
    {
        internal readonly IOptions options;
        internal readonly IHttpHandler OriginalHandler;

        public OpenIDHttpHandler(IHttpHandler originalHandler)
        {
            OriginalHandler = originalHandler;
            options = Options.FromConfiguration;
        }

        public void ProcessRequest(HttpContext application)
        {
            // Strip the leading ~ from the AppRelative path.
            var appRelativePath = application.Request.AppRelativeCurrentExecutionFilePath;
            appRelativePath = (!String.IsNullOrEmpty(appRelativePath)) ? appRelativePath.Substring(1) : String.Empty;

            var modulePath = options.RPOptions.ModulePath;

            if (appRelativePath.StartsWith(modulePath, StringComparison.OrdinalIgnoreCase))
            {
                var commandName = appRelativePath.Substring(modulePath.Length);

                var command = CommandFactory.GetCommand(commandName);
                var commandResult = RunCommand(application, command, options);

                commandResult.SignInSessionAuthenticationModule();
                commandResult.Apply(new HttpResponseWrapper(application.Response));
            }
            else
            {
                OriginalHandler.ProcessRequest(application);
            }
        }

        private static CommandResult RunCommand(HttpContext application, ICommand command, IOptions options)
        {
            try
            {
                return command.Run(new HttpRequestWrapper(application.Request).ToHttpRequestData(), options, application.Session);
            }
            catch (OIDCException)
            {
                return new CommandResult
                {
                    HttpStatusCode = HttpStatusCode.InternalServerError
                };
            }
        }

        public bool IsReusable
        {
            // IsReusable must be set to false since class has a member!
            get { return false; }
        }
    }
}
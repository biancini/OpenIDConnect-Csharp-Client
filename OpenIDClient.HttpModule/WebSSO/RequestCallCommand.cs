namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Web;
    using System.Web.SessionState;
    using System.Collections.Generic;
    using Jose;
    using OpenIDClient.Messages;
    using OpenIDClient.HttpModule.Configuration;

    class RequestCallCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request, IOptions options, HttpSessionState session)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            string body = "";

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.OK,
                Content = body
            };
        }
    }
}

namespace OpenIDClient.HttpModule.WebSso
{
    using System.Net;
    using System.Web;
    using System.Web.SessionState;
    using OpenIDClient.HttpModule.Configuration;

    class NotFoundCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request, IOptions options, HttpSessionState session)
        {
            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.NotFound
            };
        }
    }
}

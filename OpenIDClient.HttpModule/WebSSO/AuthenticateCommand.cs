namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Web;
    using System.Web.SessionState;
    using System.Collections.Generic;
    using OpenIDClient.Messages;
    using OpenIDClient.HttpModule.Configuration;

    class AuthenticateCommand : ICommand
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

            var urls = new OpenIDUrls(request, options.RPOptions);

            string rpEntityId = request.QueryString["rp"].FirstOrDefault();
            OpenIDProviderElement rp = options.OpenIDProviders[rpEntityId];
            
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = rp.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = urls.CodeCallbackCommand.ToString();
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            session.Add("op", rpEntityId);
            session.Add("nonce", requestMessage.Nonce);
            session.Add("state", requestMessage.State);

            //OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);
            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(rp.AuthorizationEndpoint + "?" + requestMessage.SerializeToQueryString())
            };
        }
    }
}

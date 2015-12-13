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

            string rpEntityId = request.QueryString["rp"].FirstOrDefault().Replace('+', ' ');
            OpenIDProviderData providerData = options.OpenIDProviders[rpEntityId];
            var urls = new OpenIDUrls(options.RPOptions, request.ApplicationUrl);
            
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = providerData.ClientInformation.ClientId;
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
                Location = new Uri(providerData.ProviderMatadata.AuthorizationEndpoint + "?" + requestMessage.SerializeToQueryString())
            };
        }
    }
}

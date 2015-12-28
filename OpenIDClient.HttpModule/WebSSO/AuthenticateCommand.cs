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
            var providerData = options.OpenIDProviders[rpEntityId];
            var urls = new OpenIDUrls(options.RPOptions, request.ApplicationUrl);
            providerData.RegisterClient(options.RPOptions, urls);

            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage(providerData, urls);
            string requestObject = null;

            if (options.RPOptions.SignCertificate != null)
            {
                OIDCAuthorizationRequestMessage rObject = generateRequestObject(providerData, urls, requestMessage.State, requestMessage.Nonce);
                //requestMessage.RequestUri = urls.RequestCommand;
                requestObject = JWT.Encode(rObject.SerializeToJsonString(), options.RPOptions.SignCertificate, JwsAlgorithm.RS256);
            }

            if (options.RPOptions.EncCertificate != null)
            {
                if (requestObject == null)
                {
                    OIDCAuthorizationRequestMessage rObject = generateRequestObject(providerData, urls, requestMessage.State, requestMessage.Nonce);
                    requestObject = rObject.SerializeToJsonString();
                }

                //requestMessage.RequestUri = urls.RequestCommand;
                requestObject = JWT.Encode(requestObject, options.RPOptions.EncCertificate, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);
            }

            session.Add("op", rpEntityId);
            session.Add("nonce", requestMessage.Nonce);
            session.Add("state", requestMessage.State);

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(providerData.ProviderMatadata.AuthorizationEndpoint + "?" + requestMessage.SerializeToQueryString())
            };
        }

        private OIDCAuthorizationRequestMessage generateRequestMessage(OpenIDProviderData providerData, OpenIDUrls urls)
        {
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = providerData.ClientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = urls.CodeCallbackCommand.ToString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.Validate();

            return requestMessage;
        }

        private OIDCAuthorizationRequestMessage generateRequestObject(OpenIDProviderData providerData, OpenIDUrls urls, string state, string nonce)
        {
            OIDCAuthorizationRequestMessage requestObject = new OIDCAuthorizationRequestMessage();
            requestObject.Iss = providerData.ClientInformation.ClientId;
            requestObject.Aud = providerData.ProviderMatadata.Issuer;
            requestObject.ClientId = providerData.ClientInformation.ClientId;
            requestObject.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestObject.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestObject.RedirectUri = urls.CodeCallbackCommand.ToString();
            requestObject.State = state;
            requestObject.Nonce = nonce;
            requestObject.Validate();

            return requestObject;
        }
    }
}

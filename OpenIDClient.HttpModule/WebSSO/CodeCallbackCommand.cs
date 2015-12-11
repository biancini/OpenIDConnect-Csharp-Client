namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Web.SessionState;
    using System.Collections.Generic;
    using OpenIDClient.Messages;
    using OpenIDClient.HttpModule.Configuration;

    class CodeCallbackCommand : ICommand
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

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            var scope = new List<MessageScope>() { MessageScope.Openid };
            var state = session["state"];
            OIDCAuthCodeResponseMessage authResponse = rp.ParseAuthCodeResponse(request.Url.Query, scope);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = authResponse.Scope;
            tokenRequestMessage.State = authResponse.State;
            tokenRequestMessage.Code = authResponse.Code;
            tokenRequestMessage.ClientId = options.OpenIDProviders[session["op"] as string].ClientId;
            tokenRequestMessage.ClientSecret = options.OpenIDProviders[session["op"] as string].ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";

            OIDCClientInformation clientInformation = new OIDCClientInformation
            {
                ClientId = tokenRequestMessage.ClientId,
                ClientSecret = tokenRequestMessage.ClientSecret,
            };
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(options.OpenIDProviders[session["op"] as string].TokenEndpoint, tokenRequestMessage, clientInformation);

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());
            requestClaims.IdToken.Add("family_name", new OIDClaimData());
            requestClaims.IdToken.Add("given_name", new OIDClaimData());
            requestClaims.IdToken.Add("locale", new OIDClaimData());
            requestClaims.IdToken.Add("email", new OIDClaimData());


            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = authResponse.Scope;
            userInfoRequestMessage.State = authResponse.State;
            userInfoRequestMessage.Claims = requestClaims;

            var urlInfoUrl = options.OpenIDProviders[session["op"] as string].UserinfoEndpoint;
            OIDCUserInfoResponseMessage response = rp.GetUserInfo(urlInfoUrl, userInfoRequestMessage, tokenResponse.AccessToken);
            ///////

            //var principal = new ClaimsPrincipal(samlResponse.GetClaims(options));
            //principal = options.SPOptions.SystemIdentityModelIdentityConfiguration
            //    .ClaimsAuthenticationManager.Authenticate(null, principal);

            string ReturnUrl = request.QueryString["ReturnUrl"].FirstOrDefault()?? urls.ApplicationBase.ToString();
            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(ReturnUrl)
            };
        }


    }
}

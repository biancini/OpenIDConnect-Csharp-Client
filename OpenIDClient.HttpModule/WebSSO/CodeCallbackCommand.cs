namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Web.SessionState;
    using System.Collections.Generic;
    using System.Security.Claims;
    using OpenIDClient.Messages;
    using OpenIDClient.HttpModule.Configuration;

    class CodeCallbackCommand : ICommand
    {
        private OpenIdRelyingParty rp = new OpenIdRelyingParty();

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

            var urls = new OpenIDUrls(options.RPOptions, request.ApplicationUrl);

            OIDCAuthCodeResponseMessage authResponse = GetAuthResponse(request, session);
            OIDCTokenResponseMessage tokenResponse = GetToken(authResponse, options, session, urls.CodeCallbackCommand.ToString());

            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(authResponse, options, session, tokenResponse.AccessToken);

            var principal = GetPrincipal(userInfoResponse, options, session);
            string ReturnUrl = request.QueryString["ReturnUrl"].FirstOrDefault()?? urls.ApplicationBase.ToString();

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(ReturnUrl),
                Principal = principal
            };
        }

        private OIDCAuthCodeResponseMessage GetAuthResponse(HttpRequestData request, HttpSessionState session)
        {
            var scope = new List<MessageScope>() { MessageScope.Openid };
            var state = session["state"];
            return rp.ParseAuthCodeResponse(request.Url.Query, scope);
        }

        private OIDCTokenResponseMessage GetToken(OIDCAuthCodeResponseMessage authResponse, IOptions options, HttpSessionState session, string redirectUri)
        {
            OpenIDProviderData providerData = options.OpenIDProviders[session["op"] as string];

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = authResponse.Scope;
            tokenRequestMessage.State = authResponse.State;
            tokenRequestMessage.Code = authResponse.Code;
            tokenRequestMessage.ClientId = providerData.ClientInformation.ClientId;
            tokenRequestMessage.ClientSecret = providerData.ClientInformation.ClientSecret;
            tokenRequestMessage.RedirectUri = redirectUri;
            tokenRequestMessage.GrantType = "authorization_code";

            OIDCTokenResponseMessage response = rp.SubmitTokenRequest(providerData.ProviderMatadata.TokenEndpoint, tokenRequestMessage, providerData.ClientInformation);
            OIDCIdToken idToken = response.GetIdToken(providerData.ProviderMatadata.Keys, tokenRequestMessage.ClientSecret);
            rp.ValidateIdToken(idToken, providerData.ClientInformation, providerData.ProviderMatadata.Issuer, null);
            return response;
        }

        private OIDCUserInfoResponseMessage GetUserInfo(OIDCAuthCodeResponseMessage authResponse, IOptions options, HttpSessionState session, string accessToken)
        {
            OpenIDProviderData providerData = options.OpenIDProviders[session["op"] as string];
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());
            requestClaims.IdToken.Add("family_name", new OIDClaimData());
            requestClaims.IdToken.Add("given_name", new OIDClaimData());
            requestClaims.IdToken.Add("email", new OIDClaimData());
            requestClaims.IdToken.Add("gender", new OIDClaimData());

            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = authResponse.Scope;
            userInfoRequestMessage.State = authResponse.State;
            userInfoRequestMessage.Claims = requestClaims;

            var urlInfoUrl = providerData.ProviderMatadata.UserinfoEndpoint;
            return rp.GetUserInfo(urlInfoUrl, userInfoRequestMessage, accessToken);
        }

        private ClaimsPrincipal GetPrincipal(OIDCUserInfoResponseMessage userInfoResponse, IOptions options, HttpSessionState session)
        {
            OpenIDProviderData providerData = options.OpenIDProviders[session["op"] as string];
            string issuer = providerData.ProviderMatadata.Issuer;

            List<Claim> c = new List<Claim>();
            if (userInfoResponse.Name != null) c.Add(new Claim(ClaimTypes.Name, userInfoResponse.Name, ClaimValueTypes.String, issuer));
            if (userInfoResponse.FamilyName != null) c.Add(new Claim(ClaimTypes.Surname, userInfoResponse.FamilyName, ClaimValueTypes.String, issuer));
            if (userInfoResponse.GivenName != null) c.Add(new Claim(ClaimTypes.GivenName, userInfoResponse.GivenName, ClaimValueTypes.String, issuer));
            if (userInfoResponse.Email != null) c.Add(new Claim(ClaimTypes.Email, userInfoResponse.Email, ClaimValueTypes.String, issuer));
            if (userInfoResponse.Gender != null) c.Add(new Claim(ClaimTypes.Gender, userInfoResponse.Gender, ClaimValueTypes.String, issuer));
            c.Add(new Claim(ClaimTypes.Role, "User"));

            ClaimsIdentity ci = new ClaimsIdentity(c, "OpenIDAuthentication", ClaimTypes.Name, ClaimTypes.Role);
            ClaimsPrincipal principal = new ClaimsPrincipal(ci);
            return options.RPOptions.SystemIdentityModelIdentityConfiguration.ClaimsAuthenticationManager.Authenticate(null, principal);
        }
    }
}

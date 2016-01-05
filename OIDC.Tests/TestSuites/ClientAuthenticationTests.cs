namespace OIDC.Tests
{
    using System.Security.Cryptography;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ClientAuthenticationTests : OIDCTests
    {
       [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();
            RegisterClient(ResponseType.Code);
            GetProviderMetadata();
        }

        /// <summary>
        /// Can make Access Token Request with 'client_secret_basic' authentication
        /// 
        /// Description:	
        /// Use the 'client_secret_basic' method to authenticate at the Authorization Server when
        /// using the token endpoint.
        /// Expected result:
        /// A Token Response, containing an ID token.
        /// </summary>
        [TestCase]
        [Category("ClientAuthenticationTests")]
        public void Should_Authenticate_Client_With_Client_Secret_Basic()
        {
            rpid = "rp-token_endpoint-client_secret_basic";

            // given
            OIDCAuthCodeResponseMessage response = (OIDCAuthCodeResponseMessage) GetAuthResponse(ResponseType.Code);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation.TokenEndpointAuthMethod = "client_secret_basic";
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }

        /// <summary>
        /// Can make Access Token Request with 'client_secret_jwt' authentication
        /// 
        /// Description:	
        /// Use the 'client_secret_jwt' method to authenticate at the Authorization Server when
        /// using the token endpoint.
        /// Expected result:	
        /// A Token Response, containing an ID token.
        /// </summary>
        [TestCase]
        [Category("ClientAuthenticationTests")]
        public void Should_Authenticate_Client_With_Client_Secret_Jwt()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthCodeResponseMessage response = (OIDCAuthCodeResponseMessage)GetAuthResponse(ResponseType.Code);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation.TokenEndpointAuthMethod = "client_secret_jwt";
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }

        /// <summary>
        /// Can make Access Token Request with 'client_secret_post' authentication
        /// 
        /// Description:	
        /// Use the 'client_secret_post' method to authenticate at the Authorization Server when
        /// using the token endpoint.
        /// Expected result:	
        /// A Token Response, containing an ID token.
        /// </summary>
        [TestCase]
        [Category("ClientAuthenticationTests")]
        public void Should_Authenticate_Client_With_Client_Secret_Post()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthCodeResponseMessage response = (OIDCAuthCodeResponseMessage)GetAuthResponse(ResponseType.Code);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation.TokenEndpointAuthMethod = "client_secret_post";
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }

        /// <summary>
        /// Can make Access Token Request with 'private_key_jwt' authentication
        /// 
        /// Description:	
        /// Use the 'private_key_jwt' method to authenticate at the Authorization Server when
        /// using the token endpoint.
        /// Expected result:	
        /// A Token Response, containing an ID token.
        /// </summary>
        [TestCase]
        [Category("ClientAuthenticationTests")]
        public void Should_Authenticate_Client_With_Private_Key_Jwt()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthCodeResponseMessage response = (OIDCAuthCodeResponseMessage)GetAuthResponse(ResponseType.Code);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            RSACryptoServiceProvider privateKey = providerMetadata.Keys.Find(
                delegate(OIDCKey k)
                {
                    return k.Use == "enc" && k.Kty == "RSA";
                }
            ).GetRSA();

            // when
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation.TokenEndpointAuthMethod = "private_key_jwt";
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation, privateKey.ExportCspBlob(false));

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }
    }
}
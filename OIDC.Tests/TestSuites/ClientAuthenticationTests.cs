namespace OIDC.Tests
{
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using Jose;

    [TestFixture]
    public class ClientAuthenticationTests : OIDCTests
    {
        OIDCClientInformation clientInformation;
        OIDCProviderMetadata providerMetadata;

        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();

            string hostname = GetBaseUrl("/");
            string registrationEndopoint = GetBaseUrl("/registration");

            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
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
        public void Should_Authenticate_Client_With_Client_Secret_Basic()
        {
            rpid = "rp-token_endpoint-client_secret_basic";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
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
        public void Should_Authenticate_Client_With_Client_Secret_Jwt()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
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
        public void Should_Authenticate_Client_With_Client_Secret_Post()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
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
        public void Should_Authenticate_Client_With_Private_Key_Jwt()
        {
            rpid = "rp-token_endpoint-client_secret_jwt";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
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
            ).getRSA();

            // when
            clientInformation.TokenEndpointAuthMethod = "private_key_jwt";
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation, privateKey.ExportCspBlob(false));

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }
    }
}
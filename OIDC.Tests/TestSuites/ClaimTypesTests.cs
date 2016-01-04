namespace OIDC.Tests
{
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ClaimTypesTests : OIDCTests
    {
        OIDCClientInformation clientInformation;
        OIDCProviderMetadata providerMetadata;

        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();

            string registrationEndopoint = GetBaseUrl("/registration");

            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
        }

        private OIDCAuthCodeResponseMessage GetAuthResponse()
        {
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid, MessageScope.Profile, MessageScope.Address, MessageScope.Phone, MessageScope.Email };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            return rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
        }

        private OIDCTokenResponseMessage GetToken(OIDCAuthCodeResponseMessage authResponse)
        {
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = authResponse.Scope;
            tokenRequestMessage.State = authResponse.State;
            tokenRequestMessage.Code = authResponse.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];
            tokenRequestMessage.GrantType = "authorization_code";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            OIDCTokenResponseMessage response = rp.SubmitTokenRequest(providerMetadata.TokenEndpoint, tokenRequestMessage, clientInformation);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys, tokenRequestMessage.ClientSecret);
            rp.ValidateIdToken(idToken, clientInformation, providerMetadata.Issuer, null);
            return response;
        }

        private OIDCUserInfoResponseMessage GetUserInfo(OIDCAuthCodeResponseMessage authResponse, string accessToken)
        {
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = authResponse.Scope;
            userInfoRequestMessage.State = authResponse.State;
            
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            var urlInfoUrl = providerMetadata.UserinfoEndpoint;
            return rp.GetUserInfo(urlInfoUrl, userInfoRequestMessage, accessToken);
        }

        /// <summary>
        /// Can use Aggregated Claims
        /// 
        /// Description:
        /// Make a UserInfo Request and read the Aggregated Claims.
        /// Expected result:	
        /// Understand the aggregated claims in the UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("ClaimTypesTests")]
        public void Should_Use_Aggregate_Claims()
        {
            rpid = "rp-claims-aggregated";
            claims = "aggregated";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            string hostname = GetBaseUrl("/");
            providerMetadata = rp.ObtainProviderInformation(hostname);

            OIDCAuthCodeResponseMessage authResponse = GetAuthResponse();
            OIDCTokenResponseMessage tokenResponse = GetToken(authResponse);
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();

            // when
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(authResponse, tokenResponse.AccessToken);

            // then
            Assert.NotNull(userInfoResponse);
            Assert.AreEqual(userInfoResponse.CustomClaims["eye_color"], "blue");
            Assert.AreEqual(userInfoResponse.CustomClaims["shoe_size"], 8);
        }

        /// <summary>
        /// Can use Distributed Claims
        /// 
        /// Description:	
        /// Make a UserInfo Request and read the Distributed Claims.
        /// Expected result:	
        /// Understand the distributed claims in the UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("ClaimTypesTests")]
        public void Should_Use_Distributed_Claims()
        {
            rpid = "rp-claims-distributed";
            claims = "distributed";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            string hostname = GetBaseUrl("/");
            providerMetadata = rp.ObtainProviderInformation(hostname);

            OIDCAuthCodeResponseMessage authResponse = GetAuthResponse();
            OIDCTokenResponseMessage tokenResponse = GetToken(authResponse);
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();

            // when
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(authResponse, tokenResponse.AccessToken);

            // then
            Assert.NotNull(userInfoResponse);
            Assert.AreEqual(userInfoResponse.CustomClaims["age"], 30);
        }
    }
}
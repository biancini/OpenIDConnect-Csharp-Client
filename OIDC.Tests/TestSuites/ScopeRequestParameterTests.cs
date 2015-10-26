namespace OIDC.Tests
{
    using System.Net;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ScopeRequestParameterTests : OIDCTests
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
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
            clientMetadata.ResponseTypes = new List<string>() { "id_token" };

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        /// <summary>
        /// 'openid' scope value should be present in the Authentication Request
        /// 
        /// Description:	
        /// Always add the openid scope value when sending an Authentication Request.
        /// Expected result:	
        /// An authentication response.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Missing required openid scope")]
        public void Should_OpenId_Missing_Scope_Throw_Exception()
        {
            rpid = "rp-scope-contains_openid_scope";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.Scope = new List<string>() { "wrong_scope" };
            
            // when
            requestMessage.Validate();
            
            // then
        }

        /// <summary>
        /// Can request and use claims using scope values.
        /// 
        /// Description:	
        /// Request claims using scope values.
        /// Expected result:	
        /// A UserInfo Response containing the requested claims. If no access token is issued
        /// (when using Implicit Flow with response_type='id_token') the ID Token contains the
        /// requested claims.
        /// </summary>
        [TestCase]
        public void Should_Authenticate_With_Claims_In_Scope_Basic()
        {
            rpid = "rp-scope-userinfo_claims";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.Userinfo = new Dictionary<string, OIDClaimData>();
            requestClaims.Userinfo.Add("name", new OIDClaimData());

            requestMessage.Scope = new List<string>() { "openid", "profile", "email", "address", "phone" };
            requestMessage.ResponseType = "id_token token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage authResponse = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = authResponse.Scope;
            userInfoRequestMessage.State = authResponse.State;

            // when
            OIDCUserInfoResponseMessage response = rp.GetUserInfo(GetBaseUrl("/userinfo"), userInfoRequestMessage, authResponse.AccessToken);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
            Assert.IsNotNullOrEmpty(response.GivenName);
            Assert.IsNotNullOrEmpty(response.FamilyName);
            Assert.IsNotNullOrEmpty(response.Email);
            Assert.IsNotNull(response.Address);
            Assert.IsNotNullOrEmpty(response.Address.StreetAddress);
            Assert.IsNotNullOrEmpty(response.Address.PostalCode);
            Assert.IsNotNullOrEmpty(response.Address.Locality);
            Assert.IsNotNullOrEmpty(response.Address.Country);
            Assert.IsNotNullOrEmpty(response.PhoneNumber);
        }

        /// <summary>
        /// Can request and use claims using scope values.
        /// 
        /// Description:	
        /// Request claims using scope values.
        /// Expected result:	
        /// A UserInfo Response containing the requested claims. If no access token is issued
        /// (when using Implicit Flow with response_type='id_token') the ID Token contains the
        /// requested claims.
        /// </summary>
        [TestCase]
        public void Should_Authenticate_With_Claims_In_Scope_Self_Issued()
        {
            rpid = "rp-scope-userinfo_claims";
            WebRequest.RegisterPrefix("openid", new OIDCWebRequestCreate());

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.RedirectUris[0];
            requestMessage.Scope = new List<string>() { "openid", "profile", "email", "address", "phone" };
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.ResponseType = "id_token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCAuthImplicitResponseMessage response = rp.Authenticate("openid://", requestMessage);
            OIDCIdToken idToken = response.GetIdToken();

            // then
            response.Validate();
            rp.ValidateIdToken(idToken, clientInformation, idToken.Iss, requestMessage.Nonce);
            Assert.IsNotNullOrEmpty(idToken.Name);
            Assert.IsNotNullOrEmpty(idToken.GivenName);
            Assert.IsNotNullOrEmpty(idToken.FamilyName);
            Assert.IsNotNullOrEmpty(idToken.Email);
            Assert.IsNotNull(idToken.Address);
            Assert.IsNotNullOrEmpty(idToken.Address.StreetAddress);
            Assert.IsNotNullOrEmpty(idToken.Address.PostalCode);
            Assert.IsNotNullOrEmpty(idToken.Address.Locality);
            Assert.IsNotNullOrEmpty(idToken.Address.Country);
            Assert.IsNotNullOrEmpty(idToken.PhoneNumber);
        }
    }
}
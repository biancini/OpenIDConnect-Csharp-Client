namespace OIDC.Tests
{
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using System.Collections.Generic;

    [TestFixture]
    public class ClaimsRequestParameterTests : OIDCTests
    {
        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();
            RegisterClient(ResponseType.IdToken);
        }

        /// <summary>
        /// Can request and use claims in ID Token using the 'claims' request parameter
        /// 
        /// Description:	
        /// Ask for the claim 'name' using the 'claims' request parameter. Retrieve the claim from an ID Token, either by making a Token Request or by using Implicit Flow.
        /// Expected result:	
        /// An ID Token containing the requested claim.
        /// </summary>
        [TestCase]
        [Category("ClaimsRequestParameterTests")]
        public void Should_Request_And_Use_Claims_Id_Token()
        {
            rpid = "rp-response_type-id_token+token";
            signalg = "RS256";
            GetProviderMetadata();

            // given
            string Nonce = WebOperations.RandomString();
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            // when
            OIDCAuthImplicitResponseMessage response = (OIDCAuthImplicitResponseMessage) GetAuthResponse(ResponseType.IdToken, Nonce, true, requestClaims);

            // then
            response.Validate();
            Assert.NotNull(response.AccessToken);

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys, clientInformation.ClientSecret);
            rp.ValidateIdToken(idToken, clientInformation, providerMetadata.Issuer, Nonce);
            Assert.IsNotNullOrEmpty(idToken.Name);
        }

        /// <summary>
        /// Can request and use claims in UserInfo Response using the 'claims' request parameter
        /// 
        /// Description:	
        /// Ask for the claim 'name' using the 'claims' request parameter. Retrieve the claims by making a UserInfo Request.
        /// Expected result:	
        /// A UserInfo Response containing the requested claim.
        /// </summary>
        [TestCase]
        [Category("ClaimsRequestParameterTests")]
        public void Should_Request_And_Use_Claims_Userinfo()
        {
            rpid = "rp-claims_request-userinfo_claims";
            GetProviderMetadata();

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthImplicitResponseMessage authResponse = (OIDCAuthImplicitResponseMessage) GetAuthResponse(ResponseType.IdToken, null, true, requestClaims);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }
    }
}
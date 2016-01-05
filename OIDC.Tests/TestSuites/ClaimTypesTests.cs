namespace OIDC.Tests
{
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ClaimTypesTests : OIDCTests
    {
        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();
            RegisterClient(ResponseType.Code);
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

            OIDCAuthCodeResponseMessage authResponse = GetAuthResponse(ResponseType.Code, null, true) as OIDCAuthCodeResponseMessage;
            OIDCTokenResponseMessage tokenResponse = GetToken(authResponse);
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();

            // when
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(authResponse.Scope, authResponse.State, tokenResponse.AccessToken);

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

            OIDCAuthCodeResponseMessage authResponse = GetAuthResponse(ResponseType.Code, null, true) as OIDCAuthCodeResponseMessage;
            OIDCTokenResponseMessage tokenResponse = GetToken(authResponse);
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();

            // when
            OIDCUserInfoResponseMessage userInfoResponse = GetUserInfo(authResponse.Scope, authResponse.State, tokenResponse.AccessToken);

            // then
            Assert.NotNull(userInfoResponse);
            Assert.AreEqual(userInfoResponse.CustomClaims["age"], 30);
        }
    }
}
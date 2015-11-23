namespace OIDC.Tests
{
    using NUnit.Framework;
    using OpenIDClient;

    [TestFixture]
    public class DiscoveryTests : OIDCTests
    {
        /// <summary>
        /// Can discover OpenID providers using URL syntax
        /// 
        /// Description:	
        /// Use WebFinger (RFC7033) and OpenID Provider Issuer Discovery to determine the location of the OpenID Provider. The discovery should be done using URL syntax as user input identifier.
        /// Expected result:	
        /// An issuer location should be returned.
        /// </summary>
        [TestCase]
        public void Should_Discover_OpenID_Providers_Using_URL_Syntax()
        {
            rpid = "rp-discovery-webfinger_url";

            // given
            string userid = "https://" + opBaseurl.Host + ":" + opBaseurl.Port + "/" + rpid;
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            string issuer = rp.ObtainIssuerFromURL(userid, opBaseurl.ToString());

            // then
            Assert.AreEqual(issuer.TrimEnd('/'), GetBaseUrl("/").TrimEnd('/'));
        }

        /// <summary>
        /// Can discover OpenID providers using acct URI syntax
        /// 
        /// Description:	
        /// Use WebFinger (RFC7033) and OpenID Provider Issuer Discovery to determine the location of the OpenID Provider. The discovery should be done using acct URI syntax as user input identifier.
        /// Expected result:	
        /// An issuer location should be returned.
        /// </summary>
        [TestCase]
        public void Should_Discover_OpenID_Providers_Using_URI_Syntax()
        {
            rpid = "rp-discovery-webfinger_acct";

            // given
            string userid = rpid + "@" + opBaseurl.Host;
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            string issuer = rp.ObtainIssuerFromEmail(userid, opBaseurl.ToString());

            // then
            Assert.AreEqual(issuer.TrimEnd('/'), GetBaseUrl("/").TrimEnd('/'));
        }

        /// <summary>
        /// Uses "OpenID Connect Discovery"
        /// 
        /// Description:	
        /// The Relying Party should be able to determine the OpenID Provider location by using OpenID Provider Issuer Discovery.
        /// Expected result:	
        /// An issuer location should be returned.
        /// </summary>
        [TestCase]
        public void Should_Discover_OpenID_Providers()
        {
            rpid = "rp-discovery";

            // given
            string userid = "https://" + opBaseurl.Host + ":" + opBaseurl.Port + "/" + rpid;
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            string issuer = rp.ObtainIssuerFromURL(userid, opBaseurl.ToString());

            // then
            Assert.AreEqual(issuer.TrimEnd('/'), GetBaseUrl("/").TrimEnd('/'));
        }

        /// <summary>
        /// Rejects discovered issuer not matching provider configuration issuer
        /// 
        /// Description:	
        /// Retrieve OpenID Provider Configuration Information for OpenID Provider from the .well-known/openid-configuration path. Verify that the issuer in the provider configuration matches the one returned by WebFinger.
        /// Expected result:	
        /// Identify that the issuers are not matching and reject the provider configuration.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage="Wrong issuer, discarding configuration")]
        public void Should_Wrong_Discovered_Issuer_Be_Rejected()
        {
            rpid = "rp-discovery-issuer_not_matching_config";

            // given
            string hostname = GetBaseUrl("/");
            string userid = "https://" + opBaseurl.Host + ":" + opBaseurl.Port + "/" + rpid;
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            string issuer = rp.ObtainIssuerFromURL(userid, opBaseurl.ToString());
            issuer = issuer.Replace("localhost", "wrong.hostname");

            // when
            rp.ObtainProviderInformation(hostname, issuer);

            // then
        }

        /// <summary>
        /// Uses "Provider Configuration Information"
        /// 
        /// Description:	
        /// Retrieve and use the OpenID Provider Configuration Information.
        /// Expected result:	
        /// Read and use the JSON object returned from the OpenID Connect Provider.
        /// </summary>
        [TestCase]
        public void Should_Obtain_Provider_Information()
        {
            rpid = "rp-discovery-openid_configuration";

            // given
            string hostname = GetBaseUrl("/");
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCProviderMetadata response = rp.ObtainProviderInformation(hostname);

            // then
            response.Validate();
        }

        /// <summary>
        /// Uses keys discovered with jwks_uri value
        /// 
        /// Description:	
        /// The Relying Party uses keys from the jwks_uri which has been obtained from the OpenID Provider Metadata.
        /// Expected result:
        /// Should be able to verify signed responses and/or encrypt requests using obtained keys.
        /// </summary>
        [TestCase]
        public void Should_Obtain_Provider_Information_With_JWKS_Json()
        {
            rpid = "rp-discovery-jwks_uri_keys";

            // given
            string hostname = GetBaseUrl("/");
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCProviderMetadata response = rp.ObtainProviderInformation(hostname);

            // then
            response.Validate();

            Assert.IsNotNull(response.Keys);
            Assert.Greater(response.Keys.Count, 0);
        }
    }
}
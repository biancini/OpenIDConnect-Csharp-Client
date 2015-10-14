using System;
using NUnit.Framework;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using FluentAssertions;
using OpenIDClient;

namespace OIDC.Tests
{
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
            // given
            rpid = "rp-discovery-webfinger_url";
            claims = "normal";
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
            // given
            rpid = "rp-discovery-webfinger_acct";
            claims = "normal";
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
            // given
            rpid = "rp-discovery";
            claims = "normal";
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
            // given
            rpid = "rp-discovery-issuer_not_matching_config";
            claims = "_";
            string hostname = GetBaseUrl("/");
            string userid = "https://" + opBaseurl.Host + ":" + opBaseurl.Port + "/" + rpid;
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            string issuer = rp.ObtainIssuerFromURL(userid, opBaseurl.ToString());

            // when
            OIDCProviderMetadata response = rp.ObtainProviderInformation(hostname, issuer);

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
            // given
            rpid = "rp-discovery-openid_configuration";
            claims = "normal";
            string hostname = GetBaseUrl("/");
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCProviderMetadata response = rp.ObtainProviderInformation(hostname);

            // then
            response.validate();
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
            // given
            rpid = "rp-discovery-jwks_uri_keys";
            claims = "normal";
            string hostname = GetBaseUrl("/");
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCProviderMetadata response = rp.ObtainProviderInformation(hostname);

            // then
            response.validate();
        }
    }
}
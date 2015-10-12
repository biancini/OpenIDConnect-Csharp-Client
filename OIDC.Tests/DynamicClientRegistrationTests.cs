using System;
using NUnit.Framework;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using FluentAssertions;
using OpenIDClient;

namespace OIDC.Tests
{
    [TestFixture]
    public class DynamicClientRegistrationTests : OIDCTests
    {
        /// <summary>
        /// Uses dynamic registration
        /// 
        /// Description:	
        /// Use the client registration endpoint in order to dynamically register the Relying Party.
        /// Expected result:	
        /// Get a Client Registration Response.
        /// </summary>
        [TestCase]
        public void Can_Register_Client()
        {
            // given
            rpid = "rp-registration-dynamic";
            claims = "normal";

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string> { "https://localhost:8090/code_flow_callback" };
            clientMetadata.ResponseTypes = new List<string> { "code" };
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCClientInformation response = rp.RegisterClient(registrationEndopoint, clientMetadata);

            // then
            response.validate();
        }
    }
}
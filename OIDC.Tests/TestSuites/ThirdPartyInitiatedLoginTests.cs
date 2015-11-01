namespace OIDC.Tests
{
    using System.Net;
    using HtmlAgilityPack;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ThirdPartyInitiatedLoginTests : OIDCTests
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
            clientMetadata.InitiateLoginUri = myBaseUrl + "initiated_login";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        /// <summary>
        /// Supports third-party initiated login
        /// 
        /// Description:	
        /// Receive a third-party initiated login request and send authentication request to the specified
        /// OpenID Connect Provider. Go to third-party initiated login test to start the test
        /// Expected result:
        /// An authentication response.
        /// </summary>
        [TestCase]
        public void Should_Spport_Third_Party_Initiated_Login()
        {
            rpid = "rp-support_3rd_party_init_login";

            // given
            OIDCThirdPartyLoginRequest thirdPartyRequest = new OIDCThirdPartyLoginRequest();
            thirdPartyRequest.Iss = GetBaseUrl("/");
            WebRequest webRequest = WebRequest.Create(clientInformation.InitiateLoginUri + "?" + thirdPartyRequest.SerializeToQueryString());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>{ "openid" };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Validate();
            request = requestMessage.SerializeToQueryString();

            param = providerMetadata.AuthorizationEndpoint;
            
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            
            // when
            WebOperations.GetUrlContent(webRequest);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result);

            // then
            response.Validate();
        }
    }
}
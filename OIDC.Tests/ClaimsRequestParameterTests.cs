using System.Net;
using System.Threading;
using HtmlAgilityPack;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SimpleWebServer;
using JWT;
using Griffin.WebServer;

using OpenIDClient;
using OpenIDClient.Messages;

namespace OIDC.Tests
{
    [TestFixture]
    public class ClaimsRequestParameterTests : OIDCTests
    {
        WebServer ws;
        OIDCClientInformation clientInformation;
        Dictionary<string, Semaphore> semaphores = new Dictionary<string, Semaphore>();
        Dictionary<string, string> results = new Dictionary<string, string>();
        IJsonSerializer JsonSerializer;

        [TestFixtureSetUp]
        public void SetupTests()
        {
            JsonSerializer = new DefaultJsonSerializer();

            X509Certificate2 certificate = new X509Certificate2("certificate.crt", "");
            ws = new WebServer(myBaseUrl.ToString(), certificate);
            ws.addUrlAction("/id_token_flow_callback", IdTokenFlowCallback);
            ws.Run();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string> {
                myBaseUrl + "id_token_flow_callback"
            };
            clientMetadata.ResponseTypes = new List<string> {
                "id_token"
            };
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
        }

        [TestFixtureTearDown]
        public void TearDownTests()
        {
            ws.Stop();
        }

        private void CodeFlowCallback(IHttpContext context)
        {
            string queryString = context.Request.Uri.Query;
            results[rpid] = queryString;
            semaphores[rpid].Release();
        }

        private void IdTokenFlowCallback(IHttpContext context)
        {
            string queryString = context.Request.Uri.Query;
            results[rpid] = queryString;
            semaphores[rpid].Release();
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
        public void Should_Request_And_Use_Claims_Id_Token()
        {
            // given
            rpid = "rp-response_type-id_token+token";
            claims = "normal";
            semaphores[rpid] = new Semaphore(0, 1);

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "id_token token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            semaphores[rpid].WaitOne();
            string queryString = results[rpid];
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(queryString, requestMessage.Scope, requestMessage.State);

            // then
            response.Validate();
            Assert.NotNull(response.AccessToken);

            string jsonToken = JsonWebToken.Decode(response.IdToken, response.AccessToken, false);
            OIDCIdToken idToken = new OIDCIdToken();
            Dictionary<string, object> o = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonToken);
            idToken.DeserializeFromDictionary(o);

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
        public void Should_Request_And_Use_Claims_Userinfo()
        {
            // given
            rpid = "rp-claims_request-userinfo_claims";
            claims = "normal";
            semaphores[rpid] = new Semaphore(0, 1);

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;


            OIDClaims requestClaims = new OIDClaims();
            requestClaims.Userinfo = new Dictionary<string, OIDClaimData>();
            requestClaims.Userinfo.Add("name", new OIDClaimData());

            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "id_token token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            semaphores[rpid].WaitOne();
            string queryString = results[rpid];
            OIDCAuthImplicitResponseMessage authResponse = rp.ParseAuthImplicitResponse(queryString, requestMessage.Scope, requestMessage.State);

            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = authResponse.Scope;
            userInfoRequestMessage.State = authResponse.State;
            
            // when
            OIDCUserInfoResponseMessage response = rp.GetUserInfo(GetBaseUrl("/userinfo"), userInfoRequestMessage, authResponse.AccessToken);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }
    }
}
namespace OIDC.Tests
{
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Text;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Jose;

    [TestFixture]
    public class ClaimsRequestParameterTests : OIDCTests
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
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
            clientMetadata.ResponseTypes = new List<string>() { "id_token" };
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
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
            rpid = "rp-response_type-id_token+token";
            signalg = "RS256";

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = "id_token token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string hostname = GetBaseUrl("/");
            providerMetadata = rp.ObtainProviderInformation(hostname);

            // when
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            string queryString = result;
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(queryString, requestMessage.Scope, requestMessage.State);

            // then
            response.Validate();
            Assert.NotNull(response.AccessToken);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            foreach (OIDCKey curKey in providerMetadata.Keys)
            {
                if (curKey.Use == "sig" && curKey.Kty == "RSA")
                {
                    var modBytes = Base64UrlEncoder.DecodeBytes(curKey.N);
                    rsa.ImportParameters(
                        new RSAParameters
                        {
                            Exponent = Base64UrlEncoder.DecodeBytes(curKey.E),
                            Modulus = modBytes
                        }
                    );
                }
            }

            string jsonToken = JWT.Decode(response.IdToken, rsa);
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
            rpid = "rp-claims_request-userinfo_claims";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.Userinfo = new Dictionary<string, OIDClaimData>();
            requestClaims.Userinfo.Add("name", new OIDClaimData());

            requestMessage.Scope = new List<string>() { "openid" };
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
        }
    }
}
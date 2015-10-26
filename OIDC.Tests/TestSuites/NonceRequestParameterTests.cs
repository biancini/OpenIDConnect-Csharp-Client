namespace OIDC.Tests
{
    using System.Net;
    using System.Security.Cryptography;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using Jose;

    [TestFixture]
    public class NonceRequestParameterTests : OIDCTests
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
        /// Sends 'nonce' unless using code flow
        /// 
        /// Description:	
        /// Always send a 'nonce' value as a request parameter while using implicit or hybrid flow.
        /// Verify the 'nonce' value returned in the ID Token.
        /// Expected result:	
        /// An ID Token, either from the Authorization Endpoint or from the Token Endpoint, containing the
        /// same 'nonce' value as passed in the authentication request when using hybrid flow or
        /// implicit flow.
        /// </summary>
        [TestCase]
        public void Should_Nonce_Be_Present_In_Implicit()
        {
            rpid = "rp-nonce-unless_code_flow";

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
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);
            RSACryptoServiceProvider rsa = providerMetadata.Keys.Find(
                delegate(OIDCKey k)
                {
                    return k.Use == "sig" && k.Kty == "RSA";
                }
            ).getRSA();

            OIDCIdToken idToken = response.GetIdToken(rsa);

            // then
            idToken.Validate();
        }

        /// <summary>
        /// Sends 'nonce' unless using code flow
        /// 
        /// Description:	
        /// Always send a 'nonce' value as a request parameter while using implicit or hybrid flow.
        /// Verify the 'nonce' value returned in the ID Token.
        /// Expected result:	
        /// An ID Token, either from the Authorization Endpoint or from the Token Endpoint, containing the
        /// same 'nonce' value as passed in the authentication request when using hybrid flow or
        /// implicit flow.
        /// </summary>
        [TestCase]
        public void Should_Nonce_Be_Present_In_Self_Issued()
        {
            rpid = "rp-nonce-unless_code_flow";
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
        }

        /// <summary>
        /// Rejects ID Token with invalid 'nonce' when valid 'nonce' sent
        /// 
        /// Description:	
        /// Pass a 'nonce' value in the Authentication Request. Verify the 'nonce' value returned in the ID Token.
        /// Expected result:
        /// Identity that the 'nonce' value in the ID Token is invalid and reject the ID Token.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong nonce value in token.")]
        public void Should_Reject_Id_Token_With_Wrong_Nonce()
        {
            rpid = "rp-nonce-invalid";

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
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);
            RSACryptoServiceProvider rsa = providerMetadata.Keys.Find(
                delegate(OIDCKey k)
                {
                    return k.Use == "sig" && k.Kty == "RSA";
                }
            ).getRSA();

            OIDCIdToken idToken = response.GetIdToken(rsa);

            // then
            rp.ValidateIdToken(idToken, clientInformation, idToken.Iss, "wrong-nonce");
        }
    }
}
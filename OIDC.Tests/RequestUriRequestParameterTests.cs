namespace OIDC.Tests
{
    using System.Net;
    using HtmlAgilityPack;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Jose;

    [TestFixture]
    public class RequestUriRequestParameterTests : OIDCTests
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
            clientMetadata.RequestUris = new List<string> { myBaseUrl + "request.jwt" };
            clientMetadata.RedirectUris = new List<string> { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<string> { "code" };
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        /// <summary>
        /// Can use request_uri request parameter with encrypted request
        /// 
        /// Description:	
        /// Pass a Request Object by Reference, using the request_uri parameter. Encrypt the Request Object
        /// using the 'RSA1_5' and 'A128CBC-HS256' algorithms.
        /// Expected result:
        /// An authentication response to the encrypted request passed using the request_uri request parameter.
        /// </summary>
        [TestCase]
        public void Should_Use_Request_Uri_Parameter_Encrypted()
        {
            // given
            rpid = "rp-request_uri-enc";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "code";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.RequestUri = myBaseUrl + "request.jwt";
            requestMessage.Validate();

            OIDCAuthorizationRequestMessage requestObject = new OIDCAuthorizationRequestMessage();
            requestObject.Iss = clientInformation.ClientId;
            requestObject.Aud = opBaseurl.ToString();
            requestObject.ClientId = clientInformation.ClientId;
            requestObject.Scope = "openid";
            requestObject.ResponseType = "code";
            requestObject.RedirectUri = clientInformation.RedirectUris[0];
            requestObject.State = requestMessage.State;
            requestObject.Nonce = requestMessage.Nonce;
            requestObject.Validate();

            X509Certificate2 certificate = new X509Certificate2("server.pfx", "");
            //RSACryptoServiceProvider key = certificate.PrivateKey as RSACryptoServiceProvider;
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.ImportParameters(
                new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                    Modulus = certificate.GetPublicKey()
                }
            );

            int k = certificate.GetPublicKey().Length / 8;
            int mlen = requestObject.SerializeToJsonString().Length;

            request = JWT.Encode(requestObject.SerializeToJsonString(), key, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            
            // when
            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can use request_uri request parameter with unsigned request
        /// 
        /// Description:
        /// Pass a Request Object by Reference, using the request_uri parameter. The Request Object should be signed using the algorithm 'none' (Unsecured JWS).
        /// Expected result:
        /// An authentication response to the unsigned request passed using the request_uri request parameter.
        /// </summary>
        [TestCase]
        public void Should_Use_Request_Uri_Parameter_Unsigned()
        {
            // given
            rpid = "rp-request_uri-unsigned";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "code";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.RequestUri = myBaseUrl + "request.jwt";
            requestMessage.Validate();

            X509Certificate2 certificate = new X509Certificate2("server.pfx", "");

            OIDCAuthorizationRequestMessage requestObject = new OIDCAuthorizationRequestMessage();
            requestObject.Iss = clientInformation.ClientId;
            requestObject.Aud = opBaseurl.ToString();
            requestObject.ClientId = clientInformation.ClientId;
            requestObject.Scope = "openid";
            requestObject.ResponseType = "code";
            requestObject.RedirectUri = clientInformation.RedirectUris[0];
            requestObject.State = requestMessage.State;
            requestObject.Nonce = requestMessage.Nonce;
            requestObject.Validate();

            request = JWT.Encode(requestObject.SerializeToJsonString(), null, JwsAlgorithm.none);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }
    }
}
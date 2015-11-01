namespace OIDC.Tests
{
    using System;
    using System.Net;
    using HtmlAgilityPack;
    using System.Collections.Generic;
    using NUnit.Framework;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Jose;
    using OpenIDClient;
    using OpenIDClient.Messages;

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
            clientMetadata.RequestUris = new List<string>() { myBaseUrl + "request.jwt" };
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        private OIDCAuthorizationRequestMessage generateRequestMessage()
        {
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.RequestUri = myBaseUrl + "request.jwt";
            requestMessage.Validate();

            return requestMessage;
        }

        private OIDCAuthorizationRequestMessage generateRequestObject(string state, string nonce)
        {
            OIDCAuthorizationRequestMessage requestObject = new OIDCAuthorizationRequestMessage();
            requestObject.Iss = clientInformation.ClientId;
            requestObject.Aud = opBaseurl.ToString();
            requestObject.ClientId = clientInformation.ClientId;
            requestObject.Scope = new List<string>() { "openid" };
            requestObject.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestObject.RedirectUri = clientInformation.RedirectUris[0];
            requestObject.State = state;
            requestObject.Nonce = nonce;
            requestObject.Validate();

            return requestObject;
        }

        private RSACryptoServiceProvider getSignKey()
        {
            X509Certificate2 certificate = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            RSACryptoServiceProvider signKey = certificate.PrivateKey as RSACryptoServiceProvider;

            byte[] privateKeyBlob = signKey.ExportCspBlob(true);
            CspParameters cp = new CspParameters(24);
            signKey = new RSACryptoServiceProvider(cp);
            signKey.ImportCspBlob(privateKeyBlob);

            return signKey;
        }

        private RSACryptoServiceProvider getEncKey()
        {
            RSACryptoServiceProvider encKey = providerMetadata.Keys.Find(
                delegate(OIDCKey k)
                {
                    return k.Use == "enc" && k.Kty == "RSA";
                }
            ).getRSA();

            return encKey;
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
            rpid = "rp-request_uri-enc";

            // given
            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage();
            OIDCAuthorizationRequestMessage requestObject = generateRequestObject(requestMessage.State, requestMessage.Nonce);
            RSACryptoServiceProvider encKey = getEncKey();

            request = JWT.Encode(requestObject.SerializeToJsonString(), encKey, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            
            // when
            WebOperations.GetUrlContent(WebRequest.Create(login_url));
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
            rpid = "rp-request_uri-unsigned";

            // given
            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage();
            OIDCAuthorizationRequestMessage requestObject = generateRequestObject(requestMessage.State, requestMessage.Nonce);

            request = JWT.Encode(requestObject.SerializeToJsonString(), null, JwsAlgorithm.none);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            WebOperations.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can use request_uri request parameter with signed request
        /// 
        /// Description:	
        /// Pass a Request Object by Reference, using the request_uri parameter. Sign the Request Object using the 'RS256' algorithm.
        /// Expected result:	
        /// An authentication response to the signed request passed using the request_uri request parameter.
        /// </summary>
        [TestCase]
        public void Should_Use_Request_Uri_Parameter_Signed()
        {
            rpid = "rp-request_uri-sig";

            // given
            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage();
            OIDCAuthorizationRequestMessage requestObject = generateRequestObject(requestMessage.State, requestMessage.Nonce);
            RSACryptoServiceProvider signKey = getSignKey();

            request = JWT.Encode(requestObject.SerializeToJsonString(), signKey, JwsAlgorithm.RS256);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            WebOperations.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can use request_uri request parameter with signed and encrypted request
        /// 
        /// Description:	
        /// Pass a Request Object by Reference, using the request_uri parameter. Sign the Request Object using
        /// the 'RS256' algorithm, then Encrypt the Request Object using the 'RSA1_5' and 'A128CBC-HS256' algorithms.
        /// Expected result:
        /// An authentication response to the signed and encrypted request passed using the request_uri request parameter.
        /// </summary>
        [TestCase]
        public void Should_Use_Request_Uri_Parameter_Signed_And_Encrypted()
        {
            rpid = "rp-request_uri-sig+enc";

            // given
            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage();
            OIDCAuthorizationRequestMessage requestObject = generateRequestObject(requestMessage.State, requestMessage.Nonce);

            X509Certificate2 certificate = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            RSACryptoServiceProvider signKey = getSignKey();
            RSACryptoServiceProvider encKey = getEncKey();

            request = JWT.Encode(requestObject.SerializeToJsonString(), signKey, JwsAlgorithm.RS256);
            request = JWT.Encode(request, encKey, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            WebOperations.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }
    }
}
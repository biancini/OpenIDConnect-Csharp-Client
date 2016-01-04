namespace OIDC.Tests
{
    using System;
    using System.Text;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using Jose;

    [TestFixture]
    public class KeyRotationTests : OIDCTests
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
            clientMetadata.RedirectUris = new List<string>() {
                myBaseUrl + "code_flow_callback",
                myBaseUrl + "id_token_flow_callback"
            };
            clientMetadata.ResponseTypes = new List<ResponseType>() {
                ResponseType.Code,
                ResponseType.IdToken
            };
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        private OIDCAuthorizationRequestMessage generateRequestMessage(bool UseRequestUri = false, string state = null, string nonce = null)
        {
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.State = (state != null) ? state : WebOperations.RandomString();
            requestMessage.Nonce = (nonce != null) ? nonce : WebOperations.RandomString();
            if (UseRequestUri)
            {
                requestMessage.RequestUri = myBaseUrl + "request.jwt";
            }
            requestMessage.Validate();

            return requestMessage;
        }

        private OIDCTokenResponseMessage AuthenticateAndRetrieveIdToken()
        {
            OIDCAuthorizationRequestMessage requestMessage = generateRequestMessage();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            return rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);
        }

        private RSACryptoServiceProvider getSignKey(string CertFilename)
        {
            X509Certificate2 certificate = new X509Certificate2(CertFilename, "", X509KeyStorageFlags.Exportable);
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
                delegate (OIDCKey k)
                {
                    return k.Use == "enc" && k.Kty == "RSA";
                }
            ).GetRSA();

            return encKey;
        }

        /// <summary>
        /// Supports rotation of provider's asymmetric signing keys
        /// 
        /// Description:	
        /// Request an ID Token and verify its signature.
        /// Make a new authentication and retrieve another ID Token and verify its signature.
        /// Expected result:	
        /// Successfully verify both ID Token signatures, fetching the rotated signing keys
        /// if the 'kid' claim in the JOSE header is unknown.
        /// </summary>
        [TestCase]
        [Category("KeyRotationTests")]
        public void Should_Support_Provider_Sign_Key_Rotation()
        {
            rpid = "rp-key_rotation-op_sign_key";
            signalg = "RS256";

            // given

            // when
            OIDCTokenResponseMessage tokenResponse1 = AuthenticateAndRetrieveIdToken();
            OIDCTokenResponseMessage tokenResponse2 = AuthenticateAndRetrieveIdToken();

            // then
            Assert.NotNull(tokenResponse1.IdToken);
            tokenResponse1.GetIdToken(providerMetadata.Keys);

            Assert.NotNull(tokenResponse2.IdToken);
            tokenResponse2.GetIdToken(providerMetadata.Keys);
        }

        /// <summary>
        /// Can rotate signing keys
        /// 
        /// Description:	
        /// Make a signed authentication request. Rotate the signing keys at the
        /// Relying Party's 'jwks_uri' after it has been used by OpenID Connect Provider.
        /// Make a new signed authentication request.
        /// Expected result:	
        /// The OpenID Connect Provider successfully uses the rotated signing key:
        /// a successful authentication response to both authentication requests signed
        /// using the rotated signing key.
        /// </summary>
        [TestCase]
        [Category("KeyRotationTests")]
        public void Should_Support_Signing_Key_Rotation()
        {
            rpid = "rp-key_rotation-rp_sign_key";

            // given
            RSACryptoServiceProvider signKey1 = getSignKey("server.pfx");
            OIDCAuthorizationRequestMessage requestMessage1 = generateRequestMessage(true);
            OIDCAuthorizationRequestMessage requestObject1 = generateRequestMessage(false, requestMessage1.State, requestMessage1.Nonce);

            RSACryptoServiceProvider signKey2 = getSignKey("server2.pfx");
            OIDCAuthorizationRequestMessage requestMessage2 = generateRequestMessage(true);
            OIDCAuthorizationRequestMessage requestObject2 = generateRequestMessage(false, requestMessage1.State, requestMessage1.Nonce);

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            request = JWT.Encode(requestObject1.SerializeToJsonString(), signKey1, JwsAlgorithm.RS256);
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage1);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response1 = rp.ParseAuthCodeResponse(result, requestMessage1.Scope, requestMessage1.State);

            request = JWT.Encode(requestObject2.SerializeToJsonString(), signKey1, JwsAlgorithm.RS256);
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage2);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response2 = rp.ParseAuthCodeResponse(result, requestMessage2.Scope, requestMessage2.State);

            // then
            response1.Validate();
            response2.Validate();
        }

        /// <summary>
        /// Supports rotation of provider's asymmetric encryption keys
        /// 
        /// Description:	
        /// Fetch the issuer's keys from the 'jwks_uri' and make an encrypted
        /// authentication request using the issuer's encryption keys.Fetch the issuer's
        /// keys from the jwks_uri again, and make a new encrypted request using the
        /// rotated encryption keys.
        /// Expected result:
        /// A successful authentication response to both authentication requests
        /// encrypted using rotated encryption keys.
        /// </summary>
        [TestCase]
        [Category("KeyRotationTests")]
        public void Should_Support_Provider_Crypt_Key_Rotation()
        {
            rpid = "rp-key_rotation-op_enc_key";

            // given
            OIDCAuthorizationRequestMessage requestMessage1 = generateRequestMessage(true);
            OIDCAuthorizationRequestMessage requestObject1 = generateRequestMessage(false, requestMessage1.State, requestMessage1.Nonce);
            RSACryptoServiceProvider encKey1 = getEncKey();

            OIDCAuthorizationRequestMessage requestMessage2 = generateRequestMessage(true);
            OIDCAuthorizationRequestMessage requestObject2 = generateRequestMessage(false, requestMessage2.State, requestMessage2.Nonce);
            RSACryptoServiceProvider encKey2 = getEncKey();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            request = JWT.Encode(requestObject1.SerializeToJsonString(), encKey1, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage1);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response1 = rp.ParseAuthCodeResponse(result, requestMessage1.Scope);

            request = JWT.Encode(requestObject2.SerializeToJsonString(), encKey2, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage2);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response2 = rp.ParseAuthCodeResponse(result, requestMessage2.Scope);

            // then
            response1.Validate();
            response2.Validate();
        }

        /// <summary>
        /// Can rotate encryption keys
        /// 
        /// Description:
        /// Request an encrypted ID Token and decrypt it.
        /// Rotate the encryption keys at the Relying Party's 'jwks_uri'
        /// after it has been used by the OpenID Connect Provider.
        /// Make a new request for an encrypted ID Token and decrypt it using the rotated
        /// decryption key.
        /// Expected result
        /// The OpenID Connect Provider successfully uses the rotated key:
        /// the first ID Token can decrypted using the first key and the second ID Token
        /// can be decrypted using the rotated key.
        /// </summary>
        [TestCase]
        [Category("KeyRotationTests")]
        public void Should_Support_Encryption_Key_Rotation()
        {
            rpid = "rp-key_rotation-rp_enc_key";
            signalg = "RS256";

            // given

            // when
            OIDCTokenResponseMessage tokenResponse1 = AuthenticateAndRetrieveIdToken();
            OIDCTokenResponseMessage tokenResponse2 = AuthenticateAndRetrieveIdToken();

            // then
            Assert.NotNull(tokenResponse1.IdToken);
            tokenResponse1.GetIdToken(providerMetadata.Keys);

            Assert.NotNull(tokenResponse2.IdToken);
            tokenResponse2.GetIdToken(providerMetadata.Keys);
        }   
    }
}
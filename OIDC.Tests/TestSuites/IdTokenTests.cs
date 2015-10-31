namespace OIDC.Tests
{
    using System.Net;
    using System.Text;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using Jose;

    [TestFixture]
    public class IdTokenTests : OIDCTests
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
            clientMetadata.ResponseTypes = new List<string>() { "code" };

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        /// <summary>
        /// Rejects ID Token with invalid asymmetric 'RS256' signature
        /// 
        /// Description:	
        /// Request an ID token and verify its signature using the keys provided by the Issuer.
        /// Expected result:	
        /// Identify the invalid signature and reject the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(IntegrityException))]
        public void Should_Reject_Id_Token_With_Invalid_Signature_RS256()
        {
            rpid = "rp-id_token-bad_asym_sig_rs256";
            signalg = "RS256";

            // givens
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "code" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // Manipulate keys to make them invalid
            List<OIDCKey> manipulatedKeys = new List<OIDCKey>();
            foreach (OIDCKey curKey in providerMetadata.Keys)
            {
                OIDCKey newKey = curKey.Clone() as OIDCKey;
                if (curKey.N != null)
                {
                    StringBuilder strBuilder = new StringBuilder(newKey.N);
                    strBuilder[17] = (char)(newKey.N[17] + 1);
                    newKey.N = strBuilder.ToString();
                }
                manipulatedKeys.Add(newKey);
            }

            // when
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            tokenResponse.GetIdToken(manipulatedKeys);
        }

        /// <summary>
        /// Rejects ID Token with invalid symmetric 'HS256' signature
        /// 
        /// Description:	
        /// Request an ID token and verify its signature using the 'client_secret' as MAC key.
        /// Expected result:	
        /// Identify the invalid signature and reject the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(IntegrityException))]
        public void Should_Reject_Id_Token_With_Invalid_Signature_HS256()
        {
            rpid = "rp-id_token-bad_asym_sig_hs256";
            signalg = "HS256";

            // givens
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "code" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // Manipulate keys to make them invalid
            StringBuilder strBuilder = new StringBuilder(clientInformation.ClientSecret);
            strBuilder[17] = (char)(clientInformation.ClientSecret[17] + 1);
            string manipulatedClientSecret = strBuilder.ToString();

            // when
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            tokenResponse.GetIdToken(null, manipulatedClientSecret);
        }

        /// <summary>
        /// Can request and use signed and encrypted ID Token
        /// 
        /// Description:	
        /// Request an encrypted ID Token. Decrypt the returned the ID Token and verify its signature
        /// using the keys published by the Issuer.
        /// Expected result
        /// Accept the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        public void Should_Request_And_Use_Signed_And_Encrypted_Id_Token()
        {
            rpid = "rp-id_token-sig+enc";
            signalg = "RS256";
            encalg = "RSA1_5:A128CBC-HS256";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<string>() { "code" };
            clientMetadata.IdTokenEncryptedResponseAlg = "RSA1_5";
            clientMetadata.IdTokenEncryptedResponseEnc = "A128CBC-HS256";
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";
            OIDCClientInformation clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "code" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            X509Certificate2 signCert = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            X509Certificate2 encCert = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            List<OIDCKey> myKeys = KeyManager.GetKeysJwkList(signCert, encCert);

            // when
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken(providerMetadata.Keys, null, myKeys);
            idToken.Validate();
        }

        /// <summary>
        /// Can request and use unsigned ID Token
        /// 
        /// Description:	
        /// Use Code Flow and retrieve an unsigned ID Token.
        /// Expected result:	
        /// Accept the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        public void Should_Request_And_Use_Unsigned_Id_Token()
        {
            rpid = "rp-id_token-sig_none";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            clientMetadata.ResponseTypes = new List<string>() { "code" };
            clientMetadata.IdTokenSignedResponseAlg = "none";
            OIDCClientInformation clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "code" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = response.Scope;
            tokenRequestMessage.State = response.State;
            tokenRequestMessage.Code = response.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.GrantType = "authorization_code";
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];

            // when
            OIDCTokenResponseMessage tokenResponse = rp.SubmitTokenRequest(GetBaseUrl("/token"), tokenRequestMessage, clientInformation);

            // then
            Assert.NotNull(tokenResponse.IdToken);
            OIDCIdToken idToken = tokenResponse.GetIdToken();
            idToken.Validate();
        }
    }
}
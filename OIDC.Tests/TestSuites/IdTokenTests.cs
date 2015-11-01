namespace OIDC.Tests
{
    using System;
    using System.Text;
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
            clientMetadata.RedirectUris = new List<string>() {
                myBaseUrl + "code_flow_callback",
                myBaseUrl + "id_token_flow_callback"
            };
            clientMetadata.ResponseTypes = new List<string>() {
                "code",
                "id_token"
            };

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

        /// <summary>
        /// Rejects ID Token with incorrect 'c_hash' claim when hybrid flow is used
        /// 
        /// Description:	
        /// Retrieve Authorization Code and ID Token from the Authorization Endpoint, using Hybrid Flow.
        /// Verify the c_hash value in the returned ID token. 'id_token_signed_response_alg' must NOT be
        /// 'none'
        /// Expected result:	
        /// Identify the incorrect 'c_hash' value and reject the ID Token after doing Authorization
        /// Code Validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong c_hash for the released id token.")]
        public void Should_Reject_Id_Token_With_Incorrect_C_Hash()
        {
            rpid = "rp-id_token-bad_c_hash";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "code", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            string ExpectedCHash = response.GetExpectedHash(response.Code, providerMetadata.Keys);
            idToken.Validate(GetBaseUrl("/"), clientInformation.ClientId, ExpectedCHash, null);
        }

        /// <summary>
        /// Rejects ID Token with incorrect 'at_hash' claim when response_type='id_token token'
        /// 
        /// Description:	
        /// Make an authentication request using response_type='id_token token' for Implicit Flow or
        /// response_type='code id_token token' for Hybrid Flow. Verify the 'at_hash' value in the
        /// returned ID Token.
        /// Expected result:
        /// Identify the incorrect 'at_hash' value and reject the ID Token after doing Access Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong at_hash for the released id token.")]
        public void Should_Reject_Id_Token_With_Incorrect_At_Hash()
        {
            rpid = "rp-id_token-bad_at_hash";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            string ExpectedAtHash = response.GetExpectedHash(response.AccessToken, providerMetadata.Keys);
            idToken.Validate(GetBaseUrl("/"), clientInformation.ClientId, null, ExpectedAtHash);
        }

        /// <summary>
        /// Rejects ID Token with incorrect 'iss' claim
        /// 
        /// Description:	
        /// Request an ID token and verify its 'iss' value.
        /// Expected result:	
        /// Identify the incorrect 'iss' value and reject the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong issuer in id token.")]
        public void Should_Reject_Id_Token_With_Wrong_Iss()
        {
            rpid = "rp-id_token-mismatching_issuer";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Iss = "ManipulatedIssuer";
            string ExpectedAtHash = response.GetExpectedHash(response.AccessToken, providerMetadata.Keys);
            idToken.Validate(GetBaseUrl("/"), clientInformation.ClientId, null, ExpectedAtHash);
        }

        /// <summary>
        /// Rejects ID Token without 'iat' claim
        /// 
        /// Description:	
        /// Request an ID token and verify its 'iat' value.
        /// Expected result:	
        /// Identify the missing 'iat' value and reject the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Missing iat required parameter.")]
        public void Should_Reject_Id_Token_With_Wrong_Iat()
        {
            rpid = "rp-id_token-iat";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Iat = DateTime.MinValue;
            idToken.Validate();
        }

        /// <summary>
        /// Rejects ID Token with invalid asymmetric 'ES256' signature
        /// 
        /// Description:	
        /// Request an ID token and verify its signature using the keys provided by the Issuer.
        /// Expected result:	
        /// Identify the invalid signature and reject the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(IntegrityException))]
        public void Should_Reject_Id_Token_With_Invalid_ES256_Signature()
        {
            rpid = "rp-id_token-bad_es256_sig";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

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

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(manipulatedKeys);
            idToken.Validate();
        }

        /// <summary>
        /// Rejects ID Token with invalid 'aud' claim
        /// 
        /// Description:	
        /// Request an ID token and compare its aud value to the Relying Party's 'client_id'.
        /// Expected result:	
        /// Identify that the 'aud' value is missing or doesn't match the 'client_id' and reject
        /// the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong audience for the released id token.")]
        public void Should_Reject_Id_Token_With_Wrong_Aud()
        {
            rpid = "rp-id_token-aud";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Aud = new List<string> { "ManipulatedAud" };
            idToken.Validate(GetBaseUrl("/"), clientInformation.ClientId);
        }

        /// <summary>
        /// Rejects ID Token without 'sub' claim
        /// 
        /// Description:	
        /// Request an ID token and verify it contains a sub value.
        /// Expected result:	
        /// Identify the missing 'sub' value and reject the ID Token.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Missing sub required parameter.")]
        public void Should_Reject_Id_Token_Without_Sub()
        {
            rpid = "rp-id_token-sub";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Sub = null;
            idToken.Validate();
        }

        /// <summary>
        /// Accepts ID Token without 'kid' claim in JOSE header if only one JWK supplied in 'jwks_uri'
        /// 
        /// Description:	
        /// Request an ID token and verify its signature using the keys provided by the Issuer.
        /// Expected result:	
        /// Use the single key published by the Issuer to verify the ID Tokens signature and accept
        /// the ID Token after doing ID Token validation.
        /// </summary>
        [TestCase]
        public void Should_Accept_Id_Token_Without_Kid_If_Just_One_JWK()
        {
            rpid = "rp-id_token-kid_absent_single_jwks";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            string hostname = GetBaseUrl("/");
            OIDCProviderMetadata providerMetadata = rp.ObtainProviderInformation(hostname);

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }

        /// <summary>
        /// Rejects ID Token without 'kid' claim in JOSE header if multiple JWKs supplied in 'jwks_uri'
        /// 
        /// Description:	
        /// Request an ID token and verify its signature using the keys provided by the Issuer.
        /// Expected result:	
        /// Identify that the 'kid' value is missing from the JOSE header and that the Issuer publishes
        /// multiple keys in its JWK Set document (referenced by 'jwks_uri'). Reject the ID Token since
        /// it can not be determined which key to use to verify the signature.
        /// </summary>
        [TestCase]
        [ExpectedException(typeof(ArgumentException))]
        public void Should_Reject_Id_Token_Without_Kid_If_Multiple_JWK()
        {
            rpid = "rp-id_token-kid_absent_multiple_jwks";

            // givens
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<string>() { "openid" };
            requestMessage.ResponseType = new List<string>() { "token", "id_token" };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();

            // when
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            Assert.NotNull(response.IdToken);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys);
            idToken.Validate();
        }
    }
}
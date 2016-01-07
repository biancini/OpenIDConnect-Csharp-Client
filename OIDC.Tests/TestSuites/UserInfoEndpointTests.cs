namespace OIDC.Tests
{
    using NUnit.Framework;
    using OpenIDClient;
    using OpenIDClient.Messages;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

    [TestFixture]
    public class UserInfoEndpointTests : OIDCTests
    {
        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();
            RegisterClient(ResponseType.IdToken);
            GetProviderMetadata();
        }

        /// <summary>
        /// Can send Access Token in the HTTP "Authorization" request header
        /// 
        /// Description:	
        /// Pass the access token using the "Bearer" authentication scheme while doing the UserInfo Request.
        /// Expected result:	
        /// A UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Send_AccessToken_In_HTTP_Authorization()
        {
            rpid = "rp-user_info-bearer_header";

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthImplicitResponseMessage authResponse = (OIDCAuthImplicitResponseMessage) GetAuthResponse(ResponseType.IdToken, null, true, requestClaims);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Can send Access Token as form-encoded body parameter
        /// 
        /// Description:	
        /// Pass the access token as a form-encoded body parameter while doing the UserInfo Request.
        /// Expected result:	
        /// A UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Send_AccessToken_As_Form_Encoded()
        {
            rpid = "rp-user_info-bearer_body";

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthImplicitResponseMessage authResponse = (OIDCAuthImplicitResponseMessage)GetAuthResponse(ResponseType.IdToken, null, true, requestClaims);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken, null, false);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Does not send Access Token as URI query parameter
        /// 
        /// Description:	
        /// Make a UserInfo Request without sending the Access Token in the HTTP request URI.
        /// Expected result:	
        /// A successful UserInfo Response without passing the Access Token as a query parameter.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Not_Send_AccessToken()
        {
            rpid = "rp-user_info-not_query";

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthImplicitResponseMessage authResponse = (OIDCAuthImplicitResponseMessage)GetAuthResponse(ResponseType.IdToken, null, true, requestClaims);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Can request and use signed UserInfo Response
        /// 
        /// Description:	
        /// Request signed UserInfo.
        /// Expected result:	
        /// Successful signature verification of the UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Accept_Signed_UserInfo()
        {
            rpid = "rp-user_info-sign";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.IdToken };
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
            clientMetadata.UserinfoSignedResponseAlg = "HS256";
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";
            OIDCClientInformation clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid, MessageScope.Profile, MessageScope.Address, MessageScope.Phone, MessageScope.Email };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage authResponse = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken, null, true, clientInformation.ClientSecret, null);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Can request and use encrypted UserInfo Response
        /// 
        /// Description:	
        /// Request encrypted UserInfo.Decrypt the UserInfo Response.
        /// Expected result:	
        /// A UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Accept_Encrypted_UserInfo()
        {
            rpid = "rp-user_info-enc";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.IdToken };
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
            clientMetadata.UserinfoEncryptedResponseAlg = "RSA1_5";
            clientMetadata.UserinfoEncryptedResponseEnc = "A128CBC-HS256";
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";
            OIDCClientInformation clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid, MessageScope.Profile, MessageScope.Address, MessageScope.Phone, MessageScope.Email };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage authResponse = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            X509Certificate2 encCert = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            List<OIDCKey> myKeys = KeyManager.GetKeysJwkList(null, encCert);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken, null, true, null, myKeys);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Can request and use signed and encrypted UserInfo Response
        /// 
        /// Description:	
        /// Request signed and encrypted UserInfo.Decrypt the UserInfo Response and verify its signature.
        /// Expected result:	
        /// Successful decryption and signature verification of the UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        public void Should_Accept_Signed_And_Encrypted_UserInfo()
        {
            rpid = "rp-user_info-sig+enc";

            // given
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.IdToken };
            clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
            clientMetadata.UserinfoSignedResponseAlg = "HS256";
            clientMetadata.UserinfoEncryptedResponseAlg = "RSA1_5";
            clientMetadata.UserinfoEncryptedResponseEnc = "A128CBC-HS256";
            clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";
            OIDCClientInformation clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);

            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid, MessageScope.Profile, MessageScope.Address, MessageScope.Phone, MessageScope.Email };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = requestClaims;
            requestMessage.Validate();

            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage authResponse = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            X509Certificate2 encCert = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            List<OIDCKey> myKeys = KeyManager.GetKeysJwkList(null, encCert);

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken, null, true, clientInformation.ClientSecret, myKeys);

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }

        /// <summary>
        /// Rejects UserInfo Response with invalid 'sub' claim
        ///  authResponse.IdToken
        /// Description:	
        /// Make a UserInfo Request and verify the 'sub' value of the UserInfo Response by comparing it with
        /// the ID Token's 'sub' value.
        /// Expected result:	
        /// Identify the invalid 'sub' value and reject the UserInfo Response.
        /// </summary>
        [TestCase]
        [Category("UserInfoEndpointTests")]
        [ExpectedException(typeof(OIDCException), ExpectedMessage = "Wrong sub in UserInfo, it does not match idToken's.")]
        public void Should_Reject_Userinfo_With_Invalid_Sub()
        {
            rpid = "rp-user_info-bad_sub_claim";

            // given
            OIDClaims requestClaims = new OIDClaims();
            requestClaims.IdToken = new Dictionary<string, OIDClaimData>();
            requestClaims.IdToken.Add("name", new OIDClaimData());

            OIDCAuthImplicitResponseMessage authResponse = (OIDCAuthImplicitResponseMessage)GetAuthResponse(ResponseType.IdToken, null, true, requestClaims);
            OIDCIdToken idToken = authResponse.GetIdToken(providerMetadata.Keys);
            idToken.Validate();

            // when
            OIDCUserInfoResponseMessage response = GetUserInfo(authResponse.Scope, authResponse.State, authResponse.AccessToken, idToken.Sub + "Wrong");

            // then
            response.Validate();
            Assert.IsNotNullOrEmpty(response.Name);
        }
    }
}
namespace OIDC.Tests
{
    using System.Net;
    using HtmlAgilityPack;
    using System.Collections.Generic;
    using NUnit.Framework;
    using System.Security.Cryptography.X509Certificates;
    using OpenIDClient;
    using OpenIDClient.Messages;

    [TestFixture]
    public class ResponseTypeAndModeTests : OIDCTests
    {
        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();
            RegisterClient(null);
        }

        /// <summary>
        /// Can make request using response_type 'code'
        /// 
        /// Description:	
        /// Make an authentication request using the Authorization Code Flow.
        /// Expected result:	
        /// An authentication response containing an authorization code.
        /// </summary>
        [TestCase]
        [Category("ResponseTypeAndModeTests")]
        public void Should_Authenticate_With_Code_Response_Type()
        {
            rpid = "rp-response_type-code";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            
            // when
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthCodeResponseMessage response = rp.ParseAuthCodeResponse(result, requestMessage.Scope);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can make request using response_type 'id_token'
        /// 
        /// Description:	
        /// Make an authentication request using the Implicit Flow, specifying the response_type as 'id_token'.
        /// Expected result:	
        /// An authentication response containing an ID Token.
        /// </summary>
        [TestCase]
        [Category("ResponseTypeAndModeTests")]
        public void Should_Authenticate_With_IdToken_Response_Type()
        {
            rpid = "rp-response_type-id_token";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can make request using response_type 'id_token token'
        /// 
        /// Description:
        /// Make an authentication request using the Implicit Flow, specifying the response_type as
        /// 'id_token token'
        /// Expected result:	
        /// An authentication response containing an ID Token and an Access Token.
        /// </summary>
        [TestCase]
        [Category("ResponseTypeAndModeTests")]
        public void Should_Authenticate_With_IdToken_Token_Response_Type()
        {
            rpid = "rp-response_type-id_token+token";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            response.Validate();
            Assert.NotNull(response.AccessToken);
        }

        /// <summary>
        /// Can make request using response_type='id_token token' and response_mode='form_post'
        /// 
        /// Description:	
        /// Make an authentication request with the response_type set to 'id_token token' and the
        /// response mode set to form_post.
        /// Expected result:	
        /// HTML form post response processed, resulting in query encoded parameters.
        /// </summary>
        [TestCase]
        [Category("ResponseTypeAndModeTests")]
        public void Should_Authenticate_With_IdToken_Token_Response_Type_Post()
        {
            rpid = "rp-response_mode-form_post";

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            requestMessage.ResponseMode = "form_post";
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            Dictionary<string, object> html = WebOperations.GetUrlContent(WebRequest.Create(login_url), false);

            // then
            Assert.NotNull(html);
            CollectionAssert.Contains(html.Keys, "body");
            string textHtml = (string)html["body"];
            Assert.NotNull(textHtml);
            HtmlDocument document = new HtmlDocument();
            document.LoadHtml(textHtml);
            HtmlNode formNode = document.DocumentNode.SelectNodes("//form")[0];
            Assert.NotNull(formNode);
            Assert.AreEqual(formNode.Attributes["method"].Value.ToLower(), "post");
            Assert.AreEqual(formNode.Attributes["action"].Value.ToLower(), requestMessage.RedirectUri);

            bool hasIdTokenInput = false;
            foreach (HtmlNode innode in formNode.SelectNodes("//input"))
            {
                if (innode.Attributes["name"].Value.Equals("access_token"))
                {
                    hasIdTokenInput = true;
                }
            }
            Assert.IsTrue(hasIdTokenInput);
        }

        /// <summary>
        /// Can use Self-Issued OpenID Provider
        /// 
        /// Description:	
        /// Make an authentication request to a Self-Issued OpenID Provider.
        /// Expected result:	
        /// An authentication response containing an self-issued ID Token.
        /// </summary>
        [TestCase]
        [Category("ResponseTypeAndModeTests")]
        public void Should_Authenticate_With_Self_Issued_Provider()
        {
            rpid = "rp-response_type-self_issued";
            WebRequest.RegisterPrefix("openid", new OIDCWebRequestCreate());

            // given
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.RedirectUris[1];
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Nonce = WebOperations.RandomString();
            requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken };
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Validate();

            X509Certificate2 certificate = new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable);
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OIDCAuthImplicitResponseMessage response = rp.Authenticate("openid://", requestMessage, certificate);

            // then
            OIDCIdToken idToken = response.GetIdToken();

            //The Client MUST validate that the aud (audience) Claim contains the value of the
            //redirect_uri that the Client sent in the Authentication Request as an audience.
            CollectionAssert.Contains(idToken.Aud, requestMessage.RedirectUri);
            
            //If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present
            //and its value checked to verify that it is the same value as the one that was sent in
            //the Authentication Request.
            Assert.AreEqual(requestMessage.Nonce, idToken.Nonce);
        }
    }
}
﻿using System.Net;
using HtmlAgilityPack;
using System.Collections.Generic;
using NUnit.Framework;
using OpenIDClient;
using OpenIDClient.Messages;

namespace OIDC.Tests
{
    [TestFixture]
    public class ResponseTypeAndModeTests : OIDCTests
    {
        OIDCClientInformation clientInformation;

        [TestFixtureSetUp]
        public void SetupTests()
        {
            StartWebServer();

            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";
            clientMetadata.RedirectUris = new List<string> {
                myBaseUrl + "code_flow_callback",
                myBaseUrl + "id_token_flow_callback"
            };
            clientMetadata.ResponseTypes = new List<string> {
                "code",
                "id_token"
            };
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
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
        public void Should_Authenticate_With_Code_Response_Type()
        {
            // given
            rpid = "rp-response_type-code";
            claims = "normal";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "code";
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Validate();

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
        /// Can make request using response_type 'id_token'
        /// 
        /// Description:	
        /// Make an authentication request using the Implicit Flow, specifying the response_type as 'id_token'.
        /// Expected result:	
        /// An authentication response containing an ID Token.
        /// </summary>
        [TestCase]
        public void Should_Authenticate_With_IdToken_Response_Type()
        {
            // given
            rpid = "rp-response_type-id_token";
            claims = "normal";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "id_token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            semaphore.WaitOne();
            OIDCAuthImplicitResponseMessage response = rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);

            // then
            response.Validate();
        }

        /// <summary>
        /// Can make request using response_type 'id_token token'
        /// 
        /// Description:
        /// Make an authentication request using the Implicit Flow, specifying the response_type as 'id_token token'
        /// Expected result:	
        /// An authentication response containing an ID Token and an Access Token.
        /// </summary>
        [TestCase]
        public void Should_Authenticate_With_IdToken_Token_Response_Type()
        {
            // given
            rpid = "rp-response_type-id_token+token";
            claims = "normal";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "id_token token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
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
        /// Make an authentication request with the response_type set to 'id_token token' and the response mode set to form_post.
        /// Expected result:	
        /// HTML form post response processed, resulting in query encoded parameters.
        /// </summary>
        [TestCase]
        public void Should_Authenticate_With_IdToken_Token_Response_Type_Post()
        {
            // given
            rpid = "rp-response_mode-form_post";
            claims = "normal";

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = "openid";
            requestMessage.ResponseType = "id_token token";
            requestMessage.ResponseMode = "form_post";
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Validate();

            string login_url = GetBaseUrl("/authorization") + "?" + requestMessage.SerializeToQueryString();
            OpenIdRelyingParty rp = new OpenIdRelyingParty();

            // when
            Dictionary<string, object> html = OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url), false);

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
        public void Should_Authenticate_With_Self_Issued_Provider()
        {
            // given
            rpid = "rp-response_type-self_issued";
            claims = "normal";

            WebRequest.RegisterPrefix("openid", new OIDCWebRequestCreate());

            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.RedirectUris[1];
            requestMessage.Scope = "openid";
            requestMessage.State = OpenIdRelyingParty.RandomString();
            requestMessage.Nonce = OpenIdRelyingParty.RandomString();
            requestMessage.ResponseType = "id_token";
            requestMessage.RedirectUri = clientInformation.RedirectUris[1];
            requestMessage.Validate();

            string login_url = "openid://?" + requestMessage.SerializeToQueryString();

            // when
            Dictionary<string, object> respo = OpenIdRelyingParty.GetUrlContent(WebRequest.Create(login_url));
            OIDCAuthImplicitResponseMessage response = new OIDCAuthImplicitResponseMessage();
            response.DeserializeFromDictionary(respo);

            // then
            OIDCIdToken idToken = new OIDCIdToken();
            Dictionary<string, object> o = JsonSerializer.Deserialize<Dictionary<string, object>>(response.IdToken);
            idToken.DeserializeFromDictionary(o);

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
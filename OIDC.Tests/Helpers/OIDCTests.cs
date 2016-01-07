namespace OIDC.Tests
{
    using System;
    using System.Net;
    using System.Configuration;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using Griffin.WebServer;
    using NUnit.Framework;
    using OIDC.Tests.Helpers;
    using OpenIDClient;
    using OpenIDClient.Messages;

    public class OIDCTests
    {
        protected static Uri myBaseUrl = new Uri(ConfigurationManager.AppSettings["MyBaseUrl"]);
        protected static Uri opBaseurl = new Uri(ConfigurationManager.AppSettings["TestOP"]);
        protected static string rpid = "_";
        protected static string signalg = "_";
        protected static string encalg = "_";
        protected static string errtype = "_";
        protected static string claims = "normal";

        protected static SimpleWebServer ws = null;
        protected static Semaphore semaphore = new Semaphore(0, 1);
        
        protected static string result = "";
        protected static string request = "";
        protected static string param = "";

        protected OIDCClientInformation clientInformation = null;
        protected OIDCProviderMetadata providerMetadata = null;

        public OIDCTests()
        { 
            if (ConfigurationManager.AppSettings["CheckHttpsCertificates"].ToLower() == "false")
            {
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            }
        }

        [SetUp]
        public void RunBeforeAnyTests()
        {
	        rpid = "_";
            signalg = "_";
            encalg = "_";
            errtype = "_";
            claims = "normal";
        }

        protected string GetBaseUrl(string endpoint)
        {
            string path = "/" + rpid;
            path += "/" + signalg;
            path += "/" + encalg;
            path += "/" + errtype;
            path += "/" + claims;
            path += "/" + (endpoint[0] == '/' ? endpoint.Substring(1) : endpoint);
            return new Uri(opBaseurl, path).ToString();
        }

        protected static void StartWebServer()
        {
            if (ws == null)
            {
                X509Certificate2 certificate = new X509Certificate2("certificate.crt", "");
                ws = new SimpleWebServer(myBaseUrl.ToString(), certificate);
                ws.addUrlAction("/my_public_keys.jwks", RespondWithJwks);
                ws.addUrlAction("/id_token_flow_callback", IdTokenFlowCallback);
                ws.addUrlAction("/code_flow_callback", CodeFlowCallback);
                ws.addUrlAction("/request.jwt", RequestUriCallback);
                ws.addUrlAction("/initiated_login", ThirdPartyInitiatedLoginCallback);
                ws.Run();
            }
        }

        private static void ThirdPartyInitiatedLoginCallback(IHttpContext context)
        {
            result = context.Request.Uri.Query;
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.DeserializeFromQueryString(request);

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            rp.ThirdPartyInitiatedLogin(requestMessage, param);
        }

        private static void RequestUriCallback(IHttpContext context)
        {
            HttpWorker.WriteTextToResponse(context, request);
        }

        private static void RespondWithJwks(IHttpContext context)
        {
            List<X509Certificate2> signCerts = new List<X509Certificate2>() {
                new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable),
                new X509Certificate2("server2.pfx", "", X509KeyStorageFlags.Exportable)
            };
            List<X509Certificate2> encCerts = new List<X509Certificate2>() {
                new X509Certificate2("server.pfx", "", X509KeyStorageFlags.Exportable),
                new X509Certificate2("server2.pfx", "", X509KeyStorageFlags.Exportable)
            };

            Dictionary<string, object> keysDict = KeyManager.GetKeysJwkDict(signCerts, encCerts);
            string rstring = Serializer.SerializeToJson(keysDict);
            HttpWorker.WriteTextToResponse(context, rstring);
        }

        private static void IdTokenFlowCallback(IHttpContext context)
        {
            result = context.Request.Uri.Query;
            semaphore.Release();
        }

        private static void CodeFlowCallback(IHttpContext context)
        {
            result = context.Request.Uri.Query;
            semaphore.Release();
        }

        public void RegisterClient(ResponseType? RespType, bool JWKs = false, bool RequestUri = false, bool InitateLoginUri = false)
        {
            string registrationEndopoint = GetBaseUrl("/registration");
            OIDCClientInformation clientMetadata = new OIDCClientInformation();
            clientMetadata.ApplicationType = "web";

            if (JWKs)
            {
                clientMetadata.JwksUri = myBaseUrl + "my_public_keys.jwks";
            }

            if (RequestUri)
            {
                clientMetadata.RequestUris = new List<string>() { myBaseUrl + "request.jwt" };
            }

            if (InitateLoginUri)
            {
                clientMetadata.InitiateLoginUri = myBaseUrl + "initiated_login";
            }

            if (ResponseType.IdToken == RespType)
            {
                clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.IdToken };
                clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "id_token_flow_callback" };
                
            }
            else if(ResponseType.Code == RespType)
            {
                clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };
                clientMetadata.RedirectUris = new List<string>() { myBaseUrl + "code_flow_callback" };
            }
            else
            {
                clientMetadata.ResponseTypes = new List<ResponseType>() {
                    ResponseType.Code,
                    ResponseType.IdToken
                };
                clientMetadata.RedirectUris = new List<string>() {
                    myBaseUrl + "code_flow_callback",
                    myBaseUrl + "id_token_flow_callback"
                };
            }

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            clientInformation = rp.RegisterClient(registrationEndopoint, clientMetadata);
        }

        public void GetProviderMetadata()
        {
            string hostname = GetBaseUrl("/");
            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            providerMetadata = rp.ObtainProviderInformation(hostname);
        }

        public OIDClientSerializableMessage GetAuthResponse(ResponseType RespType, string Nonce = null, bool Profile = false, OIDClaims Claims = null)
        {
            OIDCAuthorizationRequestMessage requestMessage = new OIDCAuthorizationRequestMessage();
            requestMessage.ClientId = clientInformation.ClientId;
            requestMessage.Scope = new List<MessageScope>() { MessageScope.Openid };
            requestMessage.RedirectUri = clientInformation.RedirectUris[0];
            requestMessage.Nonce = (Nonce == null) ? WebOperations.RandomString() : Nonce;
            requestMessage.State = WebOperations.RandomString();
            requestMessage.Claims = Claims;

            if (Profile)
            {
                requestMessage.Scope.Add(MessageScope.Profile);
                requestMessage.Scope.Add(MessageScope.Address);
                requestMessage.Scope.Add(MessageScope.Phone);
                requestMessage.Scope.Add(MessageScope.Email);
            }

            if (ResponseType.Code == RespType)
            {
                requestMessage.ResponseType = new List<ResponseType>() { ResponseType.Code };
            }
            else if (ResponseType.IdToken == RespType)
            {
                requestMessage.ResponseType = new List<ResponseType>() { ResponseType.IdToken, ResponseType.Token };
            }
            
            requestMessage.Validate();

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            rp.Authenticate(GetBaseUrl("/authorization"), requestMessage);
            semaphore.WaitOne();
            if (ResponseType.Code == RespType)
            {
                return rp.ParseAuthCodeResponse(result, requestMessage.Scope, requestMessage.State);
            }
            else if (ResponseType.IdToken == RespType)
            {
                return rp.ParseAuthImplicitResponse(result, requestMessage.Scope, requestMessage.State);
            }

            throw new Exception("Error in parameter passed");
        }

        public OIDCTokenResponseMessage GetToken(OIDCAuthCodeResponseMessage authResponse)
        {
            OIDCTokenRequestMessage tokenRequestMessage = new OIDCTokenRequestMessage();
            tokenRequestMessage.Scope = authResponse.Scope;
            tokenRequestMessage.State = authResponse.State;
            tokenRequestMessage.Code = authResponse.Code;
            tokenRequestMessage.ClientId = clientInformation.ClientId;
            tokenRequestMessage.ClientSecret = clientInformation.ClientSecret;
            tokenRequestMessage.RedirectUri = clientInformation.RedirectUris[0];
            tokenRequestMessage.GrantType = "authorization_code";

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            OIDCTokenResponseMessage response = rp.SubmitTokenRequest(providerMetadata.TokenEndpoint, tokenRequestMessage, clientInformation);
            OIDCIdToken idToken = response.GetIdToken(providerMetadata.Keys, tokenRequestMessage.ClientSecret);
            rp.ValidateIdToken(idToken, clientInformation, providerMetadata.Issuer, null);
            return response;
        }

        public OIDCUserInfoResponseMessage GetUserInfo(List<MessageScope> scope, string state, string accessToken, string idTokenSub = null, bool bearer = true, string ClientSecret = null, List<OIDCKey> RPKeys = null)
        {
            OIDCUserInfoRequestMessage userInfoRequestMessage = new OIDCUserInfoRequestMessage();
            userInfoRequestMessage.Scope = scope;
            userInfoRequestMessage.State = state;

            OpenIdRelyingParty rp = new OpenIdRelyingParty();
            var urlInfoUrl = providerMetadata.UserinfoEndpoint;
            return rp.GetUserInfo(urlInfoUrl, userInfoRequestMessage, accessToken, idTokenSub, bearer, ClientSecret, RPKeys);
        }
    }
}
namespace OIDC.Tests
{
    using System;
    using System.Net;
    using System.Configuration;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using Griffin.WebServer;
    using SimpleWebServer;
    using OpenIDClient;
    using NUnit.Framework;

    public class OIDCTests
    {
        protected static Uri myBaseUrl = new Uri(ConfigurationManager.AppSettings["MyBaseUrl"]);
        protected static Uri opBaseurl = new Uri(ConfigurationManager.AppSettings["TestOP"]);
        protected static string rpid = "_";
        protected static string signalg = "_";
        protected static string encalg = "_";
        protected static string errtype = "_";
        protected static string claims = "normal";

        protected static WebServer ws = null;
        protected static Semaphore semaphore = new Semaphore(0, 1);
        
        protected static string result = "";
        protected static string request = "";

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
                ws = new WebServer(myBaseUrl.ToString(), certificate);
                ws.addUrlAction("/my_public_keys.jwks", RespondWithJwks);
                ws.addUrlAction("/id_token_flow_callback", IdTokenFlowCallback);
                ws.addUrlAction("/code_flow_callback", CodeFlowCallback);
                ws.addUrlAction("/request.jwt", RequestUriCallback);
                ws.Run();
            }
        }

        private static void RequestUriCallback(IHttpContext context)
        {
            HttpWorker.WriteTextToResponse(context, request);
        }

        private static void RespondWithJwks(IHttpContext context)
        {
            X509Certificate signCert = new X509Certificate("server.pfx", "");
            X509Certificate encCert = new X509Certificate("server.pfx", "");

            Dictionary<string, object> keysDict = OpenIdRelyingParty.GetKeysJwks(signCert, encCert);

            string rstring = JsonSerializer.Serialize(keysDict);
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
    }
}
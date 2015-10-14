using System;
using System.Net;
using System.Configuration;

namespace OIDC.Tests
{
    public class OIDCTests
    {
        protected Uri myBaseUrl = new Uri(ConfigurationManager.AppSettings["MyBaseUrl"]);
        protected Uri opBaseurl = new Uri(ConfigurationManager.AppSettings["TestOP"]);
        protected string rpid = "_";
        protected string signalg = "_";
        protected string encalg = "_";
        protected string errtype = "_";
        protected string claims = "_";

        public OIDCTests()
        { 
            if (ConfigurationManager.AppSettings["CheckHttpsCertificates"].ToLower() == "false")
            {
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            }
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
    }
}
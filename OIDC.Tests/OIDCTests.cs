using System;
using NUnit.Framework;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using FluentAssertions;
using OpenIDClient;

namespace OIDC.Tests
{
    public class OIDCTests
    {
        protected Uri baseurl = new Uri("https://rp.certification.openid.net:8080/");
        protected string rpid = "_";
        protected string signalg = "_";
        protected string encalg = "_";
        protected string errtype = "_";
        protected string claims = "_";

        protected string GetBaseUrl(string endpoint)
        {
            string path = "/" + rpid;
            path += "/" + signalg;
            path += "/" + encalg;
            path += "/" + errtype;
            path += "/" + claims;
            path += "/" + (endpoint[0] == '/' ? endpoint.Substring(1) : endpoint);
            return new Uri(baseurl, path).ToString();
        }
    }
}
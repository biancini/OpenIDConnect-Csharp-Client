
namespace OpenIDClient
{
    using System;
    using System.Net;

    public class OpenIdWebRequest : WebRequest
    {
        private Uri uri;

        public OpenIdWebRequest(Uri uri)
        {
            this.uri = uri;
        }

        public override Uri RequestUri { get { return this.uri; } }
    }

    public class OIDCWebRequestCreate : IWebRequestCreate
    {
        public WebRequest Create(Uri uri)
        {
            if (uri.Scheme != "openid")
            {
                throw new NotSupportedException();
            }
            if (uri == null)
            {
                throw new ArgumentNullException();
            }

            return new OpenIdWebRequest(uri);
        }
    }
}

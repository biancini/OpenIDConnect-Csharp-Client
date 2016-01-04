namespace OpenIDClient.HttpModule.WebSso
{
    using System;
    using System.Net;
    using System.Web.SessionState;
    using System.Collections.Generic;
    using OpenIDClient.HttpModule.Configuration;
    using System.Security.Cryptography.X509Certificates;

    class JwksCallbackCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request, IOptions options, HttpSessionState session)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            Dictionary<string, object> keysDict = KeyManager.GetKeysJwkDict(options.RPOptions.SignCertificate, options.RPOptions.EncCertificate);
            string body = Serializer.SerializeToJson(keysDict);

            return new CommandResult()
            {
                HttpStatusCode = HttpStatusCode.OK,
                Content = body
            };
        }

    }
}
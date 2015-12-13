namespace OpenIDClient.HttpModule.Configuration
{
    using System;
    using System.Collections.Generic;
    using OpenIDClient.HttpModule.WebSso;
 
    public class OpenIDProviderData
    {
        public OpenIDProviderData(OpenIDProviderElement opEntry, IRPOptions options)
        {
            EntityId = opEntry.EntityId;

            LoadOPInformation(opEntry);
            LoadClientInformation(opEntry, options);
        }

        private void LoadClientInformation(OpenIDProviderElement opEntry, IRPOptions options)
        {
            if (opEntry.SelfRegistration)
            {
                OpenIdRelyingParty rp = new OpenIdRelyingParty();

                OIDCClientInformation clientMetadata = new OIDCClientInformation();
                clientMetadata.ApplicationType = "web";
                clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };
                clientMetadata.RedirectUris = new List<string>();

                foreach (string curUrl in options.BaseUrls.Split(';'))
                {
                    OpenIDUrls urls = new OpenIDUrls(options, new Uri(curUrl));
                    clientMetadata.RedirectUris.Add(urls.CodeCallbackCommand.ToString());
                }

                ClientInformation = rp.RegisterClient(ProviderMatadata.RegistrationEndpoint, clientMetadata);
            }
            else
            {
                foreach (string value in new List<string>() { opEntry.ClientId, opEntry.ClientSecret })
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        throw new ArgumentException("Missign one requred value for configuration. When configuring client without dynamic registration both clientid and clientsecred must be specified.");
                    }
                }

                ClientInformation = new OIDCClientInformation()
                {
                    ClientId = opEntry.ClientId,
                    ClientSecret = opEntry.ClientSecret,
                };
            }
        }

        private void LoadOPInformation(OpenIDProviderElement opEntry)
        {
            if (!String.IsNullOrEmpty(opEntry.OPIssuer))
            {
                OpenIdRelyingParty rp = new OpenIdRelyingParty();
                ProviderMatadata = rp.ObtainProviderInformation(opEntry.OPIssuer, opEntry.OPIssuer);
            }
            else
            {
                foreach (string value in new List<string>() { opEntry.AuthorizationEndpoint, opEntry.TokenEndpoint, opEntry.UserinfoEndpoint })
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        throw new ArgumentException("Missign one requred value for configuration. When configuring rp without isser discovery, all these fields must be specified: authorizationEndpoint, tokenEndpoint, userinfoEndpoint.");
                    }
                }

                ProviderMatadata = new OIDCProviderMetadata()
                {
                    AuthorizationEndpoint = opEntry.AuthorizationEndpoint,
                    TokenEndpoint = opEntry.TokenEndpoint,
                    UserinfoEndpoint = opEntry.UserinfoEndpoint,
                };

                if (!string.IsNullOrEmpty(opEntry.RegistrationEndpoint))
                {
                    ProviderMatadata.RegistrationEndpoint = opEntry.RegistrationEndpoint;
                }
            }
        }

        public string EntityId { get; private set; }

        public OIDCClientInformation ClientInformation { get; private set; }

        public OIDCProviderMetadata ProviderMatadata { get; private set; }
    }
}

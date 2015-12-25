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
            SelfRegistered = opEntry.SelfRegistration;

            if (!SelfRegistered)
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

        public void RegisterClient(OpenIDUrls urls)
        {
            if (SelfRegistered && ClientInformation == null)
            {
                OIDCClientInformation clientMetadata = new OIDCClientInformation();
                clientMetadata.ApplicationType = "web";
                clientMetadata.ResponseTypes = new List<ResponseType>() { ResponseType.Code };
                clientMetadata.RedirectUris = new List<string>();
                clientMetadata.RedirectUris.Add(urls.CodeCallbackCommand.ToString());
                //clientMetadata.JwksUri = urls.JwksCallbackCommand.ToString();

                OpenIdRelyingParty rp = new OpenIdRelyingParty();
                ClientInformation = rp.RegisterClient(ProviderMatadata.RegistrationEndpoint, clientMetadata);
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

        public bool SelfRegistered { get; private set; }

        public string EntityId { get; private set; }

        public OIDCClientInformation ClientInformation { get; private set; }

        public OIDCProviderMetadata ProviderMatadata { get; private set; }
    }
}

namespace OpenIDClient
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;

    /// <summary>
    /// Object describing the OP metadata.
    /// </summary>
    public class OIDCProviderMetadata : Messages.OIDClientSerializableMessage
    {
        public string Issuer { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string JwksUri { get; set; }
        public string UserinfoEndpoint { get; set; }
        public string RegistrationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public List<string> ResponseTypesSupported { get; set; }
        public List<string> IdTokenEncryptionAlgValuesSupported { get; set; }
        public List<string> ClaimTypesSupported { get; set; }
        public List<string> AcrValuesSupported { get; set; }
        public bool RequireRequestUriRegistration { get; set; }
        public bool RequestUriParameterSupported { get; set; }
        public List<string> RequestObjectEncryptionAlgValuesSupported { get; set; }
        public List<string> IdTokenSigningAlgValuesSupported { get; set; }
        public List<string> ResponseModesSupported { get; set; }
        public List<string> RequestObjectSigningAlgValuesSupported { get; set; }
        public List<string> SubjectTypesSupported { get; set; }
        public List<string> IdTokenEncryptionEncValuesSupported { get; set; }
        public List<string> TokenEndpointAuthMethodsSupported { get; set; }
        public List<string> UserinfoEncryptionAlgValuesSupported { get; set; }
        public bool RequestParameterSupported { get; set; }
        public List<string> TokenEndpointAuthSigningAlgValuesSupported { get; set; }
        public List<string> UserinfoSigningAlgValuesSupported { get; set; }
        public List<string> ScopesSupported { get; set; }
        public string EndSessionEndpoint { get; set; }
        public string Version { get; set; }
        public bool ClaimsParameterSupported { get; set; }
        public List<string> RequestObjectEncryptionEncValuesSupported { get; set; }
        public List<string> UserinfoEncryptionEncValuesSupported { get; set; }
        public List<string> ClaimsSupported { get; set; }
        public List<string> GrantTypesSupported { get; set; }
        public List<OIDCKey> Keys { get; set; }

        /// <summary>
        /// Empty constructor creating an empty message.
        /// </summary>
        public OIDCProviderMetadata()
        {
            // Empty constructor
        }

        /// <summary>
        /// Constructor deserializing message properties from dictionary.
        /// </summary>
        /// <param name="o">The dictionary object containing message properties.</param>
        public OIDCProviderMetadata(Dictionary<string, object> o)
        {
            DeserializeFromDictionary(o);

            if (JwksUri != null)
            {
                Keys = new List<OIDCKey>();
                Dictionary<string, object> jwks = OpenIdRelyingParty.GetUrlContent(WebRequest.Create(JwksUri));
                ArrayList keys = (ArrayList)jwks["keys"];
                foreach (Dictionary<string, object> key in keys)
                {
                    OIDCKey newKey = new OIDCKey(key);
                    Keys.Add(newKey);
                }
            }
        }
    }

    /// <summary>
    /// Object describing the RP client information.
    /// </summary>
    public class OIDCClientInformation : Messages.OIDClientSerializableMessage
    {
        public List<string> RedirectUris { get; set; }
        public List<string> ResponseTypes { get; set; }
        public List<string> GrantTypes { get; set; }
        public string ApplicationType { get; set; }
        public List<string> Contacts { get; set; }
        public string ClientId { get; set; }
        public DateTime ClientIdIssuedAt { get; set; }
        public string ClientName { get; set; }
        public string ClientSecret { get; set; }
        public DateTime ClientSecretExpiresAt { get; set; }
        public string LogoUri { get; set; }
        public string ClientUri { get; set; }
        public string PolicyUri { get; set; }
        public string TosUri { get; set; }
        public string JwksUri { get; set; }
        public string SectorIdentifierUri { get; set; }
        public string SubjectType { get; set; }
        public string IdTokenSignedResponseAlg { get; set; }
        public string IdTokenEncryptedResponseAlg { get; set; }
        public string IdTokenEncryptedResponseEnc { get; set; }
        public string UserinfoAuthMethod { get; set; }
        public string UserinfoSignedResponseAlg { get; set; }
        public string UserinfoEncryptedResponseAlg { get; set; }
        public string UserinfoEncryptedResponseEnc { get; set; }
        public string RequestObjectSigningAlg { get; set; }
        public string RequestObjectEncryptionAlg { get; set; }
        public string RequestObjectEncryptionEnc { get; set; }
        public string TokenEndpointAuthMethod { get; set; }
        public string TokenEndpointAuthSigningAlg { get; set; }
        public string DefaultMaxAge { get; set; }
        public string RequireAuthTime { get; set; }
        public List<string> DefaultAcrValues { get; set; }
        public string InitiateLoginUri { get; set; }
        public List<string> RequestUris { get; set; }
        public string RegistrationAccessToken { get; set; }
        public string RegistrationClientUri { get; set; }

        /// <summary>
        /// Empty constructor creating an empty message.
        /// </summary>
        public OIDCClientInformation()
        {
            // Empty constructor
        }

        /// <summary>
        /// Constructor deserializing message properties from dictionary.
        /// </summary>
        /// <param name="o">The dynamic object containing message properties.</param>
        public OIDCClientInformation(Dictionary<string, object> o)
        {
            DeserializeFromDictionary(o);
        }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (RedirectUris != null && ResponseTypes != null && RedirectUris.Count != ResponseTypes.Count)
            {
                throw new OIDCException("The redirect_uris do not match response_types.");
            }

            if (RedirectUris != null && SectorIdentifierUri != null)
            {
                List<string> siUris = new List<string>();
                dynamic uris = OpenIdRelyingParty.GetUrlContent(WebRequest.Create(SectorIdentifierUri));
                foreach (string uri in uris)
                {
                    siUris.Add(uri);
                }

                foreach (string uri in RedirectUris)
                {
                    if (!siUris.Contains(uri))
                    {
                        throw new OIDCException("The sector_identifier_uri json must include URIs from the redirect_uri array.");
                    }
                }
            }

            if (ResponseTypes != null && GrantTypes != null)
            {
                foreach (string responseType in ResponseTypes)
                {
                    if ((responseType == "code" && !GrantTypes.Contains("authorization_code")) ||
                        (responseType == "id_token" && !GrantTypes.Contains("implicit")) ||
                        (responseType == "token" && !GrantTypes.Contains("implicit")) ||
                        (responseType == "id_token" && !GrantTypes.Contains("implicit")))
                    {
                        throw new OIDCException("The response_types do not match grant_types.");
                    }
                }
            }

            List<string> listUri = new List<string> { LogoUri, ClientUri, PolicyUri, TosUri, JwksUri, SectorIdentifierUri, InitiateLoginUri, RegistrationClientUri };
            if (RedirectUris != null)
            {
                listUri.AddRange(RedirectUris);
            }
            if (RequestUris != null)
            {
                listUri.AddRange(RequestUris);
            }

            foreach (string uri in listUri)
            {
                if (uri == null)
                {
                    continue;
                }

                if (new Uri(uri).Scheme != "https")
                {
                    throw new OIDCException("Some of the URIs for the client is not on https");
                }
            }
        }
    }

    /// <summary>
    /// Object describing a security key in JWK format.
    /// </summary>
    public class OIDCKey : Messages.OIDClientSerializableMessage
    {
        public string Use { get; set; }
        public string Crv { get; set; }
        public string N { get; set; }
        public string E { get; set; }
        public string D { get; set; }
        public string P { get; set; }
        public string Q { get; set; }
        public string Y { get; set; }
        public string X { get; set; }
        public string Kid { get; set; }
        public string Kty { get; set; }

        /// <summary>
        /// Empty constructor creating an empty message.
        /// </summary>
        public OIDCKey()
        {
            // Do nothing
        }

        /// <summary>
        /// Constructor deserializing message properties from dictionary.
        /// </summary>
        /// <param name="o">The dictionary object containing message properties.</param>
        public OIDCKey(dynamic o)
        {
            DeserializeFromDictionary(o);
        }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (Use == null)
            {
                throw new OIDCException("The use parameter is missing in key.");
            }
        }

        public RSACryptoServiceProvider getRSA()
        {
            if (Kty != "RSA")
            {
                throw new OIDCException("Requesting RSA on a key which is not RSA.");
            }

            RSAParameters parameters = new RSAParameters
            {
                Exponent = Base64UrlEncoder.DecodeBytes(E),
                Modulus = Base64UrlEncoder.DecodeBytes(N)
            };
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.ImportParameters(parameters);
            return key;
        }
    }
}

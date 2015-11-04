namespace OpenIDClient
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;
    using Newtonsoft.Json.Linq;
    using System.Runtime.Serialization;

    public enum ResponseType
    {
        [EnumMember(Value = "code")]
        Code,
        [EnumMember(Value = "id_token")]
        IdToken,
        [EnumMember(Value = "token")]
        Token
    }

    public enum MessageScope
    {
        [EnumMember(Value = "openid")]
        Openid,
        [EnumMember(Value = "profile")]
        Profile,
        [EnumMember(Value = "email")]
        Email,
        [EnumMember(Value = "address")]
        Address,
        [EnumMember(Value = "phone")]
        Phone
    }

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
        public List<ResponseType> ResponseTypesSupported { get; set; }
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
                Dictionary<string, object> jwks = WebOperations.GetUrlContent(WebRequest.Create(JwksUri));
                JArray keys = (JArray)jwks["keys"];
                foreach (JToken key in keys)
                {
                    OIDCKey newKey = new OIDCKey(key.ToObject<Dictionary<string, object>>());
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
        public List<ResponseType> ResponseTypes { get; set; }
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
                dynamic uris = WebOperations.GetUrlContent(WebRequest.Create(SectorIdentifierUri));
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
                foreach (ResponseType responseType in ResponseTypes)
                {
                    if ((responseType == ResponseType.Code && !GrantTypes.Contains("authorization_code")) ||
                        (responseType == ResponseType.IdToken && !GrantTypes.Contains("implicit")) ||
                        (responseType == ResponseType.Token && !GrantTypes.Contains("implicit")))
                    {
                        throw new OIDCException("The response_types do not match grant_types.");
                    }
                }
            }

            List<string> listUri = new List<string>() { LogoUri, ClientUri, PolicyUri, TosUri, JwksUri, SectorIdentifierUri, InitiateLoginUri, RegistrationClientUri };
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
        private string InverseQ { get; set; }
        private string DP { get; set; }
        private string DQ { get; set; }

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

        /// <summary>
        /// Get the RSA crypting key.
        /// </summary>
        /// <returns>The RSA key</returns>
        public RSACryptoServiceProvider GetRSA()
        {
            if (Kty != "RSA")
            {
                throw new OIDCException("Requesting RSA on a key which is not RSA.");
            }

            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.ImportParameters(GetParameters());
            return key;
        }

        /// <summary>
        /// Method that retursn RSAParamenters for the current key.
        /// </summary>
        /// <returns>The RSAParamenters.</returns>
        public RSAParameters GetParameters()
        {
            RSAParameters par = new RSAParameters();
            par.Exponent = Base64UrlEncoder.DecodeBytes(E);
            par.Modulus = Base64UrlEncoder.DecodeBytes(N);
            par.D = Base64UrlEncoder.DecodeBytes(D);
            par.Q = Base64UrlEncoder.DecodeBytes(Q);
            if (P != null && InverseQ != null && DP != null && DQ != null)
            {
                par.P = Base64UrlEncoder.DecodeBytes(P);
                par.InverseQ = Base64UrlEncoder.DecodeBytes(InverseQ);
                par.DP = Base64UrlEncoder.DecodeBytes(DP);
                par.DQ = Base64UrlEncoder.DecodeBytes(DQ);
            }
            return par;
        }

        /// <summary>
        /// Method that sets parameters from RSAParamenter.
        /// </summary>
        /// <param name="par">The RSAParamenters to set</param>
        public void SetParams(RSAParameters par)
        {
            E = Base64UrlEncoder.EncodeBytes(par.Exponent);
            N = Base64UrlEncoder.EncodeBytes(par.Modulus);
            D = Base64UrlEncoder.EncodeBytes(par.D);
            Q = Base64UrlEncoder.EncodeBytes(par.Q);
            if (par.P != null && par.InverseQ != null && par.DP != null && par.DQ != null)
            {
                P = Base64UrlEncoder.EncodeBytes(par.P);
                InverseQ = Base64UrlEncoder.EncodeBytes(par.InverseQ);
                DP = Base64UrlEncoder.EncodeBytes(par.DP);
                DQ = Base64UrlEncoder.EncodeBytes(par.DQ);
            }
        }
    }

    /// <summary>
    /// Class representing a user address to be expressed in claims.
    /// </summary>
    public class OIDCAddress : Messages.OIDClientSerializableMessage
    {
        public string Country { get; set; }
        public string PostalCode { get; set; }
        public string StreetAddress { get; set; }
        public string Locality { get; set; }
    }
}

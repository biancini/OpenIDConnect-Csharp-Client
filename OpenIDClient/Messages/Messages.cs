namespace OpenIDClient.Messages
{
    using System;
    using System.Net;
    using System.Collections.Generic;
    using System.Text;
    using System.Security.Cryptography;
    using Jose;
    using OpenIDClient.Messages;

    /// <summary>
    /// Abstract class extended by all messages between RP e OP.
    /// </summary>
    public class OIDClientSerializableMessage : ICloneable
    {
        /// <summary>
        /// Clone method.
        /// </summary>
        /// <returns>A cloned version of the object.</returns>
        public object Clone()
        {
            return this.MemberwiseClone();
        }

        /// <summary>
        /// Method used to validate the message according to the rules specified in the
        /// protocol specification.
        /// </summary>
        public virtual void Validate()
        {
            // Empty, method that can be overloaded by children to check if deserialized data is correct
            // or throw an exception if not.
        }

        /// <summary>
        /// Method that deserializes message property values from a dynamic object as input.
        /// </summary>
        /// <param name="data">Dictionary object with the property values for the current message.</param>
        public void DeserializeFromDictionary(Dictionary<string, object> data)
        {
            Deserializer.DeserializeFromDictionary(this, data);
            this.Validate();
        }

        /// <summary>
        /// Method that deserializes message property values from a string obtained from query string.
        /// </summary>
        /// <param name="query">The query string.</param>
        public void DeserializeFromQueryString(string query)
        {
            Deserializer.DeserializeFromQueryString(this, query);
            this.Validate();
        }

        /// <summary>
        /// Method that serializes message property values to a Dictionary object.
        /// </summary>
        /// <returns>A dictionary serialization of the message.</returns>
        public Dictionary<string, object> SerializeToDictionary()
        {
            return Serializer.SerializeToDictionary(this);
        }

        /// <summary>
        /// Method that serializes message property values to a JSON string.
        /// </summary>
        /// <returns>A JSON string serialization of the message.</returns>
        public string SerializeToJsonString()
        {
            return Serializer.SerializeToJsonString(this);
        }

        /// <summary>
        /// Method that serializes message property values to a query string.
        /// </summary>
        /// <returns>A query string serialization of the message.</returns>
        public string SerializeToQueryString()
        {
            return Serializer.SerializeToQueryString(this);
        }
    }

    /// <summary>
    /// Message describing a registration request.
    /// </summary>
    public class OIDCClientRegistrationRequest : OIDClientSerializableMessage
    {
        public string ApplicationType { get; set; }
        public List<string> RedirectUris { get; set; }
        public string ClientName { get; set; }
        public string LogoUri { get; set; }
        public string SubjectType { get; set; }
        public List<string> SectorIdentifierUri { get; set; }
        public string TokenEndpointAuthMethod { get; set; }
        public string JwksUri { get; set; }
        public string IdTokenSignedResponseAlg { get; set; }
        public string IdTokenEncryptedResponseAlg { get; set; }
        public string IdTokenEncryptedResponseEnc { get; set; }
        public string UserInfoEncryptedResponseAlg { get; set; }
        public string UserInfoEncryptedResponseEnc { get; set; }
        public List<string> Contacts { get; set; }
        public List<string> RequestUris { get; set; }
        public List<ResponseType> ResponseTypes { get; set; }
        public string InitiateLoginUri { get; set; }

        private WebRequest PostRequest { get; set; }
    }

    /// <summary>
    /// Message describing an authorization request.
    /// </summary>
    public class OIDCAuthorizationRequestMessage : OIDClientSerializableMessage
    {
        public string Iss { get; set; }
        public string Aud { get; set; }
        public List<MessageScope> Scope { get; set; }
        public List<ResponseType> ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public string RequestUri { get; set; }
        public string ResponseMode { get; set; }
        public string Nonce { get; set; }
        public string Display { get; set; }
        public string Page { get; set; }
        public string Popup { get; set; }
        public string Touch { get; set; }
        public string Wap { get; set; }
        public string Prompt { get; set; }
        public string None { get; set; }
        public string Login { get; set; }
        public string Consent { get; set; }
        public int MaxAge { get; set; }
        public string UiLocales { get; set; }
        public string IdTokenHint { get; set; }
        public string LoginHint { get; set; }
        public string AcrValues { get; set; }
        public OIDClaims Claims { get; set; }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (Scope == null || Scope.Count == 0)
            {
                throw new OIDCException("Missing scope required parameter");
            }

            if (!Scope.Contains(MessageScope.Openid))
            {
                throw new OIDCException("Missing required openid scope");
            }

            if (ResponseType == null)
            {
                throw new OIDCException("Missing response_type required parameter");
            }

            if (ClientId == null)
            {
                throw new OIDCException("Missing client_id required parameter");
            }

            if (RedirectUri == null)
            {
                throw new OIDCException("Missing redirect_uri required parameter");
            }
        }
    }

    /// <summary>
    /// Message describing a third-party initiated login request.
    /// </summary>
    public class OIDCThirdPartyLoginRequest : OIDClientSerializableMessage
    {
        public string Iss { get; set; }
        public string LoginHint { get; set; }
        public string TargetLinkUri { get; set; }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (Iss == null)
            {
                throw new OIDCException("Missing iss required parameter.");
            }
        }
    }

    /// <summary>
    /// Message describing an authentication code response.
    /// </summary>
    public class OIDCAuthCodeResponseMessage : OIDCResponseWithToken
    {
        public string Code { get; set; }
        public string State { get; set; }
        public List<MessageScope> Scope { get; set; }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (Code == null)
            {
                throw new OIDCException("Missing code required parameter.");
            }
        }
    }

    /// <summary>
    /// Message describing an authentication implicit response.
    /// </summary>
    public class OIDCAuthImplicitResponseMessage : OIDCResponseWithToken
    {
        public string AccessToken { get; set; }
        public long ExpiresIn { get; set; }
        public string TokenType { get; set; }
        public List<MessageScope> Scope { get; set; }
        public string State { get; set; }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (IdToken == null)
            {
                throw new OIDCException("Missing id_token required parameter.");
            }

            if (State == null)
            {
                throw new OIDCException("Missing state required parameter.");
            }
        }
    }

    /// <summary>
    /// Abstract class describing a client authenticated message.
    /// </summary>
    public class OIDCAuthenticatedMessage : OIDClientSerializableMessage
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string ClientAssertionType { get; set; }
        public string ClientAssertion { get; set; }
    }

    /// <summary>
    /// Message describing a token request.
    /// </summary>
    public class OIDCTokenRequestMessage : OIDCAuthenticatedMessage
    {
        public string GrantType { get; set; }
        public string Code { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public List<MessageScope> Scope { get; set; }
    }

    /// <summary>
    /// Class describing a message containint an ID Token.
    /// </summary>
    public class OIDCResponseWithToken : OIDClientSerializableMessage
    {
        public string IdToken { get; set; }

        /// <summary>
        /// Method that computes the expected c_hash or at_hash to be used for verifying the id token.
        /// </summary>
        /// <param name="Code">The code or access token obtained from the authentication process.</param>
        /// <param name="OPKeys">The keys used by the OP.</param>
        /// <param name="ClientSecret">The secret key for the client.</param>
        /// <returns>The expected c_hash value.</returns>
        public string GetExpectedHash(string Code, List<OIDCKey> OPKeys = null, string ClientSecret = null)
        {
            string jsonToken = IdToken;
            ///Dictionary<string, object> headers = (Dictionary<string, object>)JWT.Headers(jsonToken);
            //string alg = (headers.ContainsKey("alg")) ? headers["alg"] as string : "none";
            //object sigKey = GetSignKey(headers, OPKeys, ClientSecret);
            //byte[] signedPayload = Signer.Sign(Code, alg, sigKey);
            //signedPayload = Arrays.SecondHalf(signedPayload);
            //return Convert.ToBase64String(signedPayload);
            return Code.Substring(Code.Length / 2, Code.Length / 2);
        }

        private object GetSignKey(Dictionary<string, object> headers, List<OIDCKey> OPKeys = null, string ClientSecret = null)
        {
            string alg = (headers.ContainsKey("alg")) ? headers["alg"] as string : "none";
            object sigKey = null;
            if (alg != "none")
            {
                string kid = (headers.ContainsKey("kid")) ? headers["kid"] as string : null;
                if (kid != null && OPKeys != null)
                {
                    if (OPKeys.Count == 1)
                    {
                        sigKey = OPKeys[0].GetRSA();
                    }
                    else
                    {
                        sigKey = OPKeys.Find(
                            delegate(OIDCKey k)
                            {
                                return k.Kid == kid;
                            }
                        ).GetRSA();
                    }
                }
                else
                {
                    sigKey = Encoding.UTF8.GetBytes(ClientSecret);
                }
            }
            return sigKey;
        }

        /// <summary>
        /// Method that returns the IDToken decoding the JWT.
        /// </summary>
        /// <param name="OPKeys">The OP keys.</param>
        /// <param name="ClientSecret">The client secret (to be used as key).</param>
        /// <param name="RPKeys">The RP keys.</param>
        /// <returns>The IdToken as an object.</returns>
        public OIDCIdToken GetIdToken(List<OIDCKey> OPKeys = null, string ClientSecret = null, List<OIDCKey> RPKeys = null)
        {
            string jsonToken = IdToken;
            Dictionary<string, object> headers = (Dictionary<string, object>)JWT.Headers(jsonToken);

            if (headers.ContainsKey("enc"))
            {
                string kid = (headers.ContainsKey("kid")) ? headers["kid"] as string : null;
                RSACryptoServiceProvider encKey = null;
                if (RPKeys.Count == 1)
                {
                    encKey = RPKeys[0].GetRSA();
                }
                else
                {
                    encKey = RPKeys.Find(
                        delegate(OIDCKey k)
                        {
                            return k.Kid == kid;
                        }
                    ).GetRSA();
                }

                jsonToken = JWT.Decode(jsonToken, encKey);
                headers = (Dictionary<string, object>)JWT.Headers(jsonToken);
            }

            object sigKey = GetSignKey(headers, OPKeys, ClientSecret);
            jsonToken = JWT.Decode(jsonToken, sigKey);
            Dictionary<string, object> o = Deserializer.DeserializeFromJson<Dictionary<string, object>>(jsonToken);
            OIDCIdToken idToken = new OIDCIdToken();
            idToken.DeserializeFromDictionary(o);

            return idToken;
        }
    }

    /// <summary>
    /// Message describing an the client secret JWT.
    /// </summary>
    public class OIDCClientSecretJWT : OIDClientSerializableMessage
    {
        public string Iss { get; set; }
        public string Sub { get; set; }
        public string Aud { get; set; }
        public string Jti { get; set; }
        public DateTime Exp { get; set; }
        public DateTime Iat { get; set; }
    }

    /// <summary>
    /// Message describing a token response.
    /// </summary>
    public class OIDCTokenResponseMessage : OIDCResponseWithToken
    {
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public string RefreshToken { get; set; }
        public long ExpiresIn { get; set; }
        
        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {
            if (AccessToken == null)
            {
                throw new OIDCException("Missing access_token required parameter.");
            }

            if (TokenType == null)
            {
                throw new OIDCException("Missing token_type required parameter.");
            }
        }
    }

    /// <summary>
    /// Message describing a user info request.
    /// </summary>
    public class OIDCUserInfoRequestMessage : OIDCAuthenticatedMessage
    {
        public List<MessageScope> Scope { get; set; }
        public string State { get; set; }
        public OIDClaims Claims { get; set; }
    }

    /// <summary>
    /// Message describing a user info response.
    /// </summary>
    public class OIDCUserInfoResponseMessage : OIDClientSerializableMessage
    {
        public string Sub { get; set; }
        public string Name { get; set; }
        public string GivenName { get; set; }
        public string FamilyName { get; set; }
        public string MiddleName { get; set; }
        public string Nickname { get; set; }
        public string PreferredUsername { get; set; }
        public string Profile { get; set; }
        public string Picture { get; set; }
        public string Website { get; set; }
        public string Email { get; set; }
        public bool EmailVerified { get; set; }
        public string Gender { get; set; }
        public string Birthdate { get; set; }
        public string Zoneinfo { get; set; }
        public string Locale { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public OIDCAddress Address { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    /// <summary>
    /// Message describing an ID token.
    /// </summary>
    public class OIDCIdToken : OIDClientSerializableMessage
    {
        public string Iss { get; set; }
        public string Sub { get; set; }
        public List<string> Aud { get; set; }
        public DateTime Exp { get; set; }
        public DateTime Iat { get; set; }
        public DateTime AuthTime { get; set; }
        public string Nonce { get; set; }
        public string Acr { get; set; }
        public List<string> Amr { get; set; }
        public string Azp { get; set; }
        public string CHash { get; set; }
        public string AtHash { get; set; }
        public OIDCKey SubJkw { get; set; }
        public string Name { get; set; }
        public string GivenName { get; set; }
        public string FamilyName { get; set; }
        public string MiddleName { get; set; }
        public string Nickname { get; set; }
        public string PreferredUsername { get; set; }
        public string Profile { get; set; }
        public string Picture { get; set; }
        public string Website { get; set; }
        public string Email { get; set; }
        public bool EmailVerified { get; set; }
        public string Gender { get; set; }
        public string Birthdate { get; set; }
        public string Zoneinfo { get; set; }
        public string Locale { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public OIDCAddress Address { get; set; }
        public DateTime UpdatedAt { get; set; }

        /// <summary>
        /// Method that validates the ID Token.
        /// </summary>
        /// <param name="ExpectedIss">Expected value for issuer.</param>
        /// <param name="ExpectedAud">Expected value for audience.</param>
        /// <param name="ExpectedCHash">Expected value for c_hash (optional).</param>
        /// <param name="ExpectedAtHash">Expected value for at_hash (optional).</param>
        public void Validate(string ExpectedIss, string ExpectedAud, string ExpectedCHash = null, string ExpectedAtHash = null)
        {
            Validate();

            if (Iss != ExpectedIss)
            {
                throw new OIDCException("Wrong issuer in id token.");
            }

            if (!Aud.Contains(ExpectedAud))
            {
                throw new OIDCException("Wrong audience for the released id token.");
            }

            if (ExpectedCHash != null && CHash != ExpectedCHash)
            {
                throw new OIDCException("Wrong c_hash for the released id token.");
            }

            if (ExpectedAtHash != null && AtHash != ExpectedAtHash)
            {
                throw new OIDCException("Wrong at_hash for the released id token.");
            }
        }

        /// <summary>
        /// <see cref="OIDClientSerializableMessage.Validate()"/>
        /// </summary>
        public override void Validate()
        {   
            if (Iss == null)
            {
                throw new OIDCException("Missing iss required parameter.");
            }

            if (Iss != "https://self-issued.me")
            {
                ValidateGeneric();
            }
        }

        private void ValidateGeneric()
        {
            if (Sub == null)
            {
                throw new OIDCException("Missing sub required parameter.");
            }

            if (Aud == null)
            {
                throw new OIDCException("Missing aud required parameter.");
            }

            if (Exp == null)
            {
                throw new OIDCException("Missing exp required parameter.");
            }

            if (Iat == DateTime.MinValue)
            {
                throw new OIDCException("Missing iat required parameter.");
            }
        }
    }

    /// <summary>
    /// Message describing claims for a request
    /// </summary>
    public class OIDClaimData : OIDClientSerializableMessage
    {
        public bool Essential { get; set; }
        public string Value { get; set; }
        public List<string> Values { get; set; }
    }

    /// <summary>
    /// Message describing claims for a request
    /// </summary>
    public class OIDClaims : OIDClientSerializableMessage
    {
        public Dictionary<string, OIDClaimData> Userinfo { get; set; }
        public Dictionary<string, OIDClaimData> IdToken { get; set; }
    }

    /// <summary>
    /// Message describing an error from the OP.
    /// </summary>
    public class OIDCResponseError : OIDClientSerializableMessage
    {
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
        public string ErrorUri { get; set; }
        public string State { get; set; }
    }
}

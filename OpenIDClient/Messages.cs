using System;
using System.Net;
using System.Collections.Generic;
using System.Reflection;
using System.Text.RegularExpressions;
using JWT;

namespace OpenIDClient.Messages
{
    public class OIDClientSerializableMessage
    {
        public virtual void validate()
        {
            // Empty, method that can be overloaded by children to check if deserialized data is correct
            // or throw an exception if not.
        }

        protected DateTime secondsUtcToDateTime(long dateValue)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            return epoch.AddSeconds(dateValue);
        }

        protected long dateTimeToSecondsUtc(DateTime dateValue)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            return (long) (dateValue - epoch).TotalSeconds;
        }

        public bool isSupportedType(Type t)
        {
            List<Type> supportedTypes = new List<Type>() {
                typeof(string),
                typeof(List<string>),
                typeof(DateTime),
                typeof(long),
                typeof(int),
                typeof(bool)
            };

            return supportedTypes.Contains(t);
        }

        public void deserializeFromDynamic(dynamic data)
        {
            PropertyInfo[] properties = this.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (PropertyInfo p in properties)
            {
                if (!isSupportedType(p.PropertyType))
                {
                    continue;
                }

                string propertyCamel = p.Name;
                string propertyUnderscore = Regex.Replace(propertyCamel, "(?<=.)([A-Z])", "_$0", RegexOptions.Compiled).ToLower();

                try
                {
                    if (data[propertyUnderscore] == null)
                    {
                        continue;
                    }
                }
                catch (KeyNotFoundException)
                {
                    continue;
                }

                if (p.PropertyType == typeof(string))
                {
                    string propertyValue = (string)data[propertyUnderscore];
                    p.SetValue(this, propertyValue);
                }
                else if (p.PropertyType == typeof(List<string>))
                {
                    List<string> propertyValue = new List<string>();
                    if (data[propertyUnderscore].GetType() == typeof(string))
                    {
                        propertyValue.Add(data[propertyUnderscore]);
                    }
                    else
                    {
                        dynamic arrayData = data[propertyUnderscore];
                        foreach (string val in arrayData)
                        {
                            propertyValue.Add(val);
                        }
                    }
                    p.SetValue(this, propertyValue);
                }
                else if (p.PropertyType == typeof(DateTime))
                {
                    DateTime propertyValue = secondsUtcToDateTime((long)data[propertyUnderscore]);
                    p.SetValue(this, propertyValue);
                }
                else if (p.PropertyType == typeof(bool))
                {
                    bool propertyValue = (bool)data[propertyUnderscore];
                    p.SetValue(this, propertyValue);
                }
                else if (p.PropertyType == typeof(int))
                {
                    int propertyValue = (int)data[propertyUnderscore];
                    p.SetValue(this, propertyValue);
                }
            }

            validate();
        }

        public void deserializeFromQueryString(string query)
        {
            if (query.StartsWith("?"))
            {
                query = query.Substring(1);
            }

            Dictionary<string, object> data = new Dictionary<string, object>();
            foreach (string param in query.Split('&'))
            {
                string[] vals = param.Split('=');
                data.Add(vals[0], Uri.UnescapeDataString(vals[1]));
            }

            if (!data.ContainsKey("error"))
            {
                deserializeFromDynamic(data);
            }
        }

        private Dictionary<string, object> getData()
        {
            PropertyInfo[] properties = this.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            Dictionary<string, object> data = new Dictionary<string, object>();
            foreach (PropertyInfo p in properties)
            {
                if (!isSupportedType(p.PropertyType))
                {
                    continue;
                }

                string propertyCamel = p.Name;
                string propertyUnderscore = Regex.Replace(propertyCamel, "(?<=.)([A-Z])", "_$0", RegexOptions.Compiled).ToLower();

                if (p.GetValue(this, null) == null)
                {
                    continue;
                }

                if (p.PropertyType == typeof(string))
                {
                    string propertyValue = (string)p.GetValue(this, null);
                    data.Add(propertyUnderscore, propertyValue);
                }
                else if (p.PropertyType == typeof(List<string>))
                {
                    List<string> propertyValue = (List<string>)p.GetValue(this, null);
                    data.Add(propertyUnderscore, propertyValue.ToArray());
                }
                else if (p.PropertyType == typeof(DateTime))
                {
                    long propertyValue = dateTimeToSecondsUtc((DateTime)p.GetValue(this, null));
                    data.Add(propertyUnderscore, propertyValue);
                }
                else if (p.PropertyType == typeof(bool))
                {
                    bool propertyValue = (bool)p.GetValue(this, null);
                    data.Add(propertyUnderscore, propertyValue);
                }
                else if (p.PropertyType == typeof(int))
                {
                    int propertyValue = (int)p.GetValue(this, null);
                    data.Add(propertyUnderscore, propertyValue);
                }
            }

            return data;
        }

        public string serializeToJsonString()
        {
            Dictionary<string, object> data = getData();
            IJsonSerializer JsonSerializer = new DefaultJsonSerializer();
            return JsonSerializer.Serialize(data);
        }

        public string serializeToQueryString()
        {
            string uri = "";
            Dictionary<string, object> data = getData();
            foreach (KeyValuePair<string, object> entry in data)
            {
                uri += entry.Key + "=" + entry.Value + "&";
            }
            return uri.TrimEnd('&');
        }
    }

    public class OIDCClientRegistrationRequest : OIDClientSerializableMessage
    {
        private WebRequest PostRequest { get; set; }

        public string ApplicationType { get; set; }
        public List<string> RedirectUris { get; set; }
        public string ClientName { get; set; }
        public string LogoUri { get; set; }
        public string SubjectType { get; set; }
        public List<string> SectorIdentifierUri { get; set; }
        public string TokenEndpointAuthMethod { get; set; }
        public string JwksUri { get; set; }
        public string UserInfoEncryptedResponseAlg { get; set; }
        public string UserInfoEncryptedResponseEnc { get; set; }
        public List<string> Contacts { get; set; }
        public List<string> RequestUris { get; set; }
        public List<string> ResponseTypes { get; set; }
    }

    public class OIDCAuthorizationRequestMessage : OIDClientSerializableMessage
    {
        public string Scope { get; set; }
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
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

        public override void validate()
        {
            if (Scope == null)
            {
                throw new OIDCException("Mising scope required parameter.");
            }

            if (ResponseType == null)
            {
                throw new OIDCException("Mising response_type required parameter.");
            }

            if (ClientId == null)
            {
                throw new OIDCException("Mising client_id required parameter.");
            }

            if (RedirectUri == null)
            {
                throw new OIDCException("Mising redirect_uri required parameter.");
            }
        }
    }

    public class OIDCAuthCodeResponseMessage : OIDClientSerializableMessage
    {
        public string Code { get; set; }
        public string State { get; set; }
        public string Scope { get; set; }

        public override void validate()
        {
            if (Code == null)
            {
                throw new OIDCException("Mising code required parameter.");
            }
        }
    }

    public class OIDCAuthImplicitResponseMessage : OIDClientSerializableMessage
    {
        public string AccessToken { get; set; }
        public long ExpiresIn { get; set; }
        public string TokenType { get; set; }
        public string IdToken { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }

        public override void validate()
        {
            if (AccessToken == null)
            {
                throw new OIDCException("Mising access_token required parameter.");
            }

            if (TokenType == null)
            {
                throw new OIDCException("Mising token_type required parameter.");
            }

            if (IdToken == null)
            {
                throw new OIDCException("Mising id_token required parameter.");
            }

            if (State == null)
            {
                throw new OIDCException("Mising state required parameter.");
            }
        }
    }

    public class OIDCAuthenticatedMessage : OIDClientSerializableMessage
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string ClientAssertionType { get; set; }
        public string ClientAssertion { get; set; }
    }

    public class OIDCTokenRequestMessage : OIDCAuthenticatedMessage
    {
        public string GrantType { get; set; }
        public string Code { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public string Scope { get; set; }
    }

    public class OIDCClientSecretJWT : OIDClientSerializableMessage
    {
        public string Iss { get; set; }
        public string Sub { get; set; }
        public string Aud { get; set; }
        public string Jti { get; set; }
        public DateTime Exp { get; set; }
        public DateTime Iat { get; set; }
    }

    public class OIDCTokenResponseMessage : OIDClientSerializableMessage
    {
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public string RefreshToken { get; set; }
        public long ExpiresIn { get; set; }
        public string IdToken { get; set; }

        public override void validate()
        {
            if (AccessToken == null)
            {
                throw new OIDCException("Mising access_token required parameter.");
            }

            if (TokenType == null)
            {
                throw new OIDCException("Mising token_type required parameter.");
            }
        }
    }

    public class OIDCUserInfoRequestMessage : OIDCAuthenticatedMessage
    {
        public string Scope { get; set; }
        public string State { get; set; }
    }

    public class OIDCUserInfoResponseMessage : OIDClientSerializableMessage
    {
        public string Sub { get; set; }
        public string Name { get; set; }
        public string GivenName { get; set; }
        public string FamilyName { get; set; }
        public string PreferredUsername { get; set; }
        public string Email { get; set; }
        public string Picture { get; set; }
    }

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
        public string AtHash { get; set; }

        public override void validate()
        {
            if (Iss == null)
            {
                throw new OIDCException("Mising iss required parameter.");
            }

            if (Sub == null)
            {
                throw new OIDCException("Mising sub required parameter.");
            }

            if (Aud == null)
            {
                throw new OIDCException("Mising aud required parameter.");
            }

            if (Exp == null)
            {
                throw new OIDCException("Mising exp required parameter.");
            }

            if (Iat == null)
            {
                throw new OIDCException("Mising iat required parameter.");
            }
        }
    }

    public class OIDCResponseError : OIDClientSerializableMessage
    {
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
        public string ErrorUri { get; set; }
        public string State { get; set; }
    }
}

namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text.RegularExpressions;
    using OpenIDClient.Messages;
    using Newtonsoft.Json.Linq;
    using System.Runtime.Serialization;
    using Newtonsoft.Json;

    public class Deserializer
    {
        private static Dictionary<Type, Delegate> ParsersPerType = new Dictionary<Type, Delegate>()
        {
            { typeof(string), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseString },
            { typeof(bool), (Action<OIDClientSerializableMessage, PropertyInfo, object>)  ParseBool },
            { typeof(int), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseInteger },
            { typeof(ResponseType), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseResponseType },
            { typeof(MessageScope), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseMessageScope },
            { typeof(List<string>), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseListString },
            { typeof(List<ResponseType>), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseListResponseType },
            { typeof(List<MessageScope>), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseListMessageScope },
            { typeof(Dictionary<string, object>), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseDictionaryStringObject },
            { typeof(DateTime), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseDateTime },
            { typeof(OIDCClientRegistrationRequest), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCAuthorizationRequestMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCThirdPartyLoginRequest), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCAuthCodeResponseMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCAuthImplicitResponseMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCTokenRequestMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCResponseWithToken), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCClientSecretJWT), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCTokenResponseMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCUserInfoRequestMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCUserInfoResponseMessage), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCIdToken), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDClaimData), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDClaims), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCResponseError), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCProviderMetadata), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCClientInformation), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCKey), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage },
            { typeof(OIDCAddress), (Action<OIDClientSerializableMessage, PropertyInfo, object>) ParseOIDCMessage }
        };

        private static void ParseString(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            string propertyValue = (string)value;
            p.SetValue(obj, propertyValue);
        }

        private static void ParseResponseType(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            if (value.GetType() == typeof(ResponseType))
            {
                p.SetValue(obj, (ResponseType)value);
            }
            else
            {
                switch (value.ToString())
                {
                    case "code":
                        p.SetValue(obj, ResponseType.Code);
                        break;
                    case "token":
                        p.SetValue(obj, ResponseType.Token);
                        break;
                    case "id_token":
                        p.SetValue(obj, ResponseType.Token);
                        break;
                }
            }
        }

        private static void ParseMessageScope(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            if (value.GetType() == typeof(MessageScope))
            {
                p.SetValue(obj, (MessageScope)value);
            }
            else
            {
                switch (value.ToString())
                {
                    case "openid":
                        p.SetValue(obj, MessageScope.Openid);
                        break;
                    case  "profile":
                        p.SetValue(obj, MessageScope.Profile);
                        break;
                    case  "email":
                        p.SetValue(obj, MessageScope.Email);
                        break;
                    case  "address":
                        p.SetValue(obj, MessageScope.Address);
                        break;
                    case "phone":
                        p.SetValue(obj, MessageScope.Phone);
                        break;
                }
            }
        }

        private static void ParseListString(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            List<string> propertyValue = new List<string>();
            if (value.GetType() == typeof(string))
            {
                propertyValue.Add((string)value);
            }
            else
            {
                dynamic arrayData = value;
                foreach (string val in arrayData)
                {
                    propertyValue.Add(val);
                }
            }

            p.SetValue(obj, propertyValue);
        }

        private static void ParseListResponseType(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            List<ResponseType> propertyValue = new List<ResponseType>();
            if (value.GetType() == typeof(ResponseType))
            {
                propertyValue.Add((ResponseType)value);
            }
            else if (value.GetType() == typeof(string))
            {
                switch (value.ToString())
                {
                    case "code":
                        propertyValue.Add(ResponseType.Code);
                        break;
                    case "token":
                        propertyValue.Add(ResponseType.Token);
                        break;
                    case "id_token":
                        propertyValue.Add(ResponseType.Token);
                        break;
                }
            }
            else if (value.GetType() == typeof(List<ResponseType>))
            {
                List<ResponseType> arrayData = (List<ResponseType>)value;
                foreach (ResponseType val in arrayData)
                {
                    propertyValue.Add(val);
                }
            }
            else
            {
                JArray arrayData = (JArray)value;
                foreach (JValue val in arrayData)
                {
                    if (!new List<string> { "code", "token", "id_token" }.Contains(val.ToString()))
                    {
                        continue;
                    }
                    propertyValue.Add(val.ToObject<ResponseType>());
                }
            }

            p.SetValue(obj, propertyValue);
        }

        private static void ParseListMessageScope(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            List<MessageScope> propertyValue = new List<MessageScope>();
            if (value.GetType() == typeof(MessageScope))
            {
                propertyValue.Add((MessageScope)value);
            }
            else if (value.GetType() == typeof(string))
            {
                switch (value.ToString())
                {
                    case "openid":
                        propertyValue.Add(MessageScope.Openid);
                        break;
                    case "profile":
                        propertyValue.Add(MessageScope.Profile);
                        break;
                    case "email":
                        propertyValue.Add(MessageScope.Email);
                        break;
                    case "address":
                        propertyValue.Add(MessageScope.Address);
                        break;
                    case "phone":
                        propertyValue.Add(MessageScope.Phone);
                        break;
                }
            }
            else if (value.GetType() == typeof(List<MessageScope>))
            {
                List<MessageScope> arrayData = (List<MessageScope>)value;
                foreach (MessageScope val in arrayData)
                {
                    propertyValue.Add(val);
                }
            }
            else
            {
                JArray arrayData = (JArray)value;
                foreach (JValue val in arrayData)
                {
                    if (!new List<string> { "openid", "profile", "email", "address", "phone" }.Contains(val.ToString()))
                    {
                        continue;
                    }
                    propertyValue.Add(val.ToObject<MessageScope>());
                }
            }

            p.SetValue(obj, propertyValue);
        }

        private static void ParseDictionaryStringObject(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            Dictionary<string, object> propertyValue = (Dictionary<string, object>)value;
            p.SetValue(obj, propertyValue);
        }

        private static void ParseDateTime(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            long dataLong = long.Parse(string.Empty + value);
            DateTime propertyValue = DateTime.MaxValue;
            if (dataLong != 0)
            {
                propertyValue = SecondsUtcToDateTime(dataLong);
            }

            p.SetValue(obj, propertyValue);
        }

        private static void ParseBool(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            bool propertyValue = bool.Parse(string.Empty + value);
            p.SetValue(obj, propertyValue);
        }

        private static void ParseInteger(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            int propertyValue = int.Parse(string.Empty + value);
            p.SetValue(obj, propertyValue);
        }

        private static void ParseOIDCMessage(OIDClientSerializableMessage obj, PropertyInfo p, object value)
        {
            OIDClientSerializableMessage propertyValue = (OIDClientSerializableMessage)Activator.CreateInstance(p.PropertyType);
            JObject curObj = (JObject)value;
            propertyValue.DeserializeFromDictionary(curObj.ToObject<Dictionary<string, object>>());
            p.SetValue(obj, propertyValue);
        }

        public static void DeserializeFromDictionary(OIDClientSerializableMessage obj, Dictionary<string, object> data)
        {
            PropertyInfo[] properties = obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (PropertyInfo p in properties)
            {
                string propertyCamel = p.Name;
                string propertyUnderscore = Regex.Replace(propertyCamel, "(?<=.)([A-Z])", "_$0", RegexOptions.Compiled).ToLower();
                Type propertyType = p.PropertyType;
                object propertyValue = (data.ContainsKey(propertyUnderscore)) ? data[propertyUnderscore] : null;

                if (!ParsersPerType.ContainsKey(p.PropertyType) || propertyValue == null)
                {
                    continue;
                }

                Delegate d = ParsersPerType[propertyType];
                d.DynamicInvoke(obj, p, propertyValue);
            }
        }

        public static void DeserializeFromQueryString(OIDClientSerializableMessage obj, string query)
        {
            string queryString = query;
            if (queryString.StartsWith("?"))
            {
                queryString = queryString.Substring(1);
            }

            Dictionary<string, object> data = new Dictionary<string, object>();
            foreach (string param in queryString.Split('&'))
            {
                string[] vals = param.Split('=');
                data.Add(vals[0], Uri.UnescapeDataString(vals[1]));
            }

            if (!data.ContainsKey("error"))
            {
                DeserializeFromDictionary(obj, data);
            }
        }

        private static DateTime SecondsUtcToDateTime(long dateValue)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            return epoch.AddSeconds(dateValue);
        }

        /// <summary>
        /// Deserialize a JSON string to typed object.
        /// </summary>
        /// <typeparam name="T">type of object</typeparam>
        /// <param name="json">JSON string</param>
        /// <returns>typed object</returns>
        public static T DeserializeFromJson<T>(string json)
        {
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}

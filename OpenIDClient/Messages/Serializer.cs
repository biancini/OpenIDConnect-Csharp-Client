namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text.RegularExpressions;
    using System.Runtime.Serialization;
    using OpenIDClient.Messages;

    public static class Serializer
    {
        private static Dictionary<Type, Delegate> ParsersPerType = new Dictionary<Type, Delegate>()
        {
            { typeof(string), (Func<object, object>) ParsePlainObject },
            { typeof(bool), (Func<object, object>) ParsePlainObject },
            { typeof(int), (Func<object, object>) ParsePlainObject },
            { typeof(ResponseType), (Func<object, object>) ParseResponseType },
            { typeof(MessageScope), (Func<object, object>) ParseMessageScope },
            { typeof(List<>), (Func<object, object>) ParseList },
            { typeof(Dictionary<,>), (Func<object, object>) ParseDictionary },
            { typeof(DateTime), (Func<object, object>) ParseDateTime },
            { typeof(OIDCClientRegistrationRequest), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCAuthorizationRequestMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCThirdPartyLoginRequest), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCAuthCodeResponseMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCAuthImplicitResponseMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCTokenRequestMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCResponseWithToken), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCClientSecretJWT), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCTokenResponseMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCUserInfoRequestMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCUserInfoResponseMessage), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCIdToken), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDClaimData), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDClaims), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCResponseError), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCProviderMetadata), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCClientInformation), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCKey), (Func<object, object>) ParseOIDCMessage },
            { typeof(OIDCAddress), (Func<object, object>) ParseOIDCMessage }
        };

        private static Type GetType(Type propertyType)
        {
            if (propertyType.IsGenericType)
            {
                if (propertyType.Name.StartsWith("List"))
                {
                    return typeof(List<>);
                }
                return propertyType.GetGenericTypeDefinition();
            }
            return propertyType;
        }

        private static long DateTimeToSecondsUtc(DateTime dateValue)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            return (long)(dateValue - epoch).TotalSeconds;
        }

        private static object ParsePlainObject(object value)
        {
            return value;
        }

        private static object ParseResponseType(object value)
        {
            string enumval = ((ResponseType)value).ToString();
            FieldInfo fi = typeof(ResponseType).GetField(enumval);
            EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
            return (attributes.Length > 0) ? attributes[0].Value : enumval;
        }

        private static object ParseMessageScope(object value)
        {
            string enumval = ((MessageScope)value).ToString();
            FieldInfo fi = typeof(MessageScope).GetField(enumval);
            EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
            return (attributes.Length > 0) ? attributes[0].Value : enumval;
        }

        private static object ParseList(object value)
        {
            Type objType = GetType(value.GetType());
            if (ParsersPerType.ContainsKey(objType) && objType != typeof(List<>))
            {
                Delegate d = ParsersPerType[objType];
                return d.DynamicInvoke(value);
            }

            return value;
        }

        private static object ParseDictionary(object value)
        {
            Dictionary<string, object> propertyValue = new Dictionary<string, object>();
            dynamic dValue = value;
            foreach (string val in dValue.Keys)
            {
                object arrValue = dValue[val];
                propertyValue.Add(val, SerializeToDictionary(arrValue));
            }
            return propertyValue;
        }

        private static object ParseDateTime(object value)
        {
            long propertyValue = 0;
            if ((DateTime)value != DateTime.MaxValue)
            {
                propertyValue = DateTimeToSecondsUtc((DateTime)value);
            }
            return propertyValue;
        }

        private static object ParseOIDCMessage(object value)
        {
            OIDClientSerializableMessage propertyValue = (OIDClientSerializableMessage)value;
            return propertyValue.SerializeToDictionary();
        }

        public static string SerializeToJsonString(OIDClientSerializableMessage obj)
        {
            Dictionary<string, object> data = SerializeToDictionary(obj);
            return SerializeToJsonString(data);
        }

        public static string SerializeToJsonString(object obj)
        {
            return OIDCJsonSerializer.Serialize(obj);
        }

        public static string SerializeToJsonString(Dictionary<string, object> obj)
        {
            return OIDCJsonSerializer.Serialize(obj);
        }

        public static Dictionary<string, object> SerializeToDictionary(object obj)
        {
            PropertyInfo[] properties = obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            Dictionary<string, object> data = new Dictionary<string, object>();
            foreach (PropertyInfo p in properties)
            {
                string propertyCamel = p.Name;
                string propertyUnderscore = Regex.Replace(propertyCamel, "(?<=.)([A-Z])", "_$0", RegexOptions.Compiled).ToLower();
                object propertyValue = p.GetValue(obj, null);
                Type propertyType = GetType(p.PropertyType);

                if (propertyValue == null || !ParsersPerType.ContainsKey(propertyType))
                {
                    continue;
                }

                Delegate d = ParsersPerType[propertyType];
                data.Add(propertyUnderscore, d.DynamicInvoke(propertyValue));
            }

            return data;
        }

        public static string SerializeToQueryString(OIDClientSerializableMessage obj)
        {
            string queryString = "";
            Dictionary<string, object> data = SerializeToDictionary(obj);
            foreach (KeyValuePair<string, object> entry in data)
            {
                string value = entry.Value.ToString();
                if (typeof(OIDClientSerializableMessage).IsAssignableFrom(entry.Value.GetType()))
                {
                    OIDClientSerializableMessage propertyValue = (OIDClientSerializableMessage)entry.Value;
                    value = SerializeToQueryString(propertyValue);
                }
                else if (entry.Value.GetType().IsGenericType)
                {
                    dynamic dValue = entry.Value;

                    if (GetType(entry.Value.GetType()) == typeof(List<>))
                    {
                        value = "";
                        foreach (object val in dValue)
                        {
                            value += (value == "") ? "" : " ";
                            if (val.GetType() == typeof(ResponseType))
                            {
                                string enumval = ((ResponseType)val).ToString();
                                FieldInfo fi = typeof(ResponseType).GetField(enumval);
                                EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
                                value += (attributes.Length > 0) ? attributes[0].Value : enumval;
                            }
                            else if (val.GetType() == typeof(MessageScope))
                            {
                                string enumval = ((MessageScope)val).ToString();
                                FieldInfo fi = typeof(MessageScope).GetField(enumval);
                                EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
                                value += (attributes.Length > 0) ? attributes[0].Value : enumval;
                            }
                            else
                            {
                                value += val.ToString();
                            }
                        }
                    }
                    else if (GetType(entry.Value.GetType()) == typeof(Dictionary<,>))
                    {
                        value = "{ ";
                        foreach (string val in dValue.Keys)
                        {
                            value += "\"" + val + "\": " + SerializeToJsonString(dValue[val]) + ",";
                        }
                        value = value.TrimEnd(',');
                        value += " }";
                    }
                }

                queryString += entry.Key + "=" + Uri.EscapeDataString(value) + "&";
            }

            return queryString.TrimEnd('&');
        }
    }
}

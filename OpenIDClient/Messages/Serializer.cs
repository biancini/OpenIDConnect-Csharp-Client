namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text.RegularExpressions;
    using System.Runtime.Serialization;
    using OpenIDClient.Messages;

    class Serializer
    {
        private static long DateTimeToSecondsUtc(DateTime dateValue)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            return (long)(dateValue - epoch).TotalSeconds;
        }

        private static object ParsePropertyType(Type propertyType, object value)
        {
            if (propertyType == typeof(string) || propertyType == typeof(bool) || propertyType == typeof(int))
            {
                return value;
            }
            else if (propertyType == typeof(ResponseType))
            {
                string enumval = ((ResponseType)value).ToString();
                FieldInfo fi = typeof(ResponseType).GetField(enumval);
                EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
                return (attributes.Length > 0) ? attributes[0].Value : enumval;
            }
            else if (propertyType.IsGenericType && propertyType.Name.StartsWith("List") || propertyType == typeof(List<>))
            {
                if (value.GetType() == typeof(ResponseType))
                {
                    string enumval = ((ResponseType)value).ToString();
                    FieldInfo fi = typeof(ResponseType).GetField(enumval);
                    EnumMemberAttribute[] attributes = (EnumMemberAttribute[])fi.GetCustomAttributes(typeof(EnumMemberAttribute), false);
                    return (attributes.Length > 0) ? attributes[0].Value : enumval;
                }

                return value;
            }
            else if (propertyType.IsGenericType && propertyType.GetGenericTypeDefinition() == typeof(Dictionary<,>))
            {
                Dictionary<string, object> propertyValue = new Dictionary<string, object>();
                dynamic dValue = value;
                foreach (string val in dValue.Keys)
                {
                    object arrValue = dValue[val];
                    propertyValue.Add(val, ParsePropertyType(arrValue.GetType(), arrValue));
                }
                return propertyValue;
            }
            else if (propertyType == typeof(DateTime))
            {
                long propertyValue = 0;
                if ((DateTime)value != DateTime.MaxValue)
                {
                    propertyValue = DateTimeToSecondsUtc((DateTime)value);
                }
                return propertyValue;
            }
            else if (typeof(OIDClientSerializableMessage).IsAssignableFrom(propertyType))
            {
                OIDClientSerializableMessage propertyValue = (OIDClientSerializableMessage)value;
                return propertyValue.SerializeToDictionary();
            }

            return value;
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

        public static Dictionary<string, object> SerializeToDictionary(OIDClientSerializableMessage obj)
        {
            PropertyInfo[] properties = obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            Dictionary<string, object> data = new Dictionary<string, object>();
            foreach (PropertyInfo p in properties)
            {
                if (!OIDClientSerializableMessage.IsSupportedType(p.PropertyType))
                {
                    continue;
                }

                string propertyCamel = p.Name;
                string propertyUnderscore = Regex.Replace(propertyCamel, "(?<=.)([A-Z])", "_$0", RegexOptions.Compiled).ToLower();

                if (p.GetValue(obj, null) == null)
                {
                    continue;
                }

                data.Add(propertyUnderscore, ParsePropertyType(p.PropertyType, p.GetValue(obj, null)));
            }

            return data;
        }

        public static string SerializeToQueryString(OIDClientSerializableMessage obj)
        {
            string uri = "";
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

                    if (entry.Value.GetType().GetGenericTypeDefinition() == typeof(List<>))
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
                            else
                            {
                                value += val.ToString();
                            }
                        }
                    }
                    else if (entry.Value.GetType().GetGenericTypeDefinition() == typeof(Dictionary<,>))
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

                uri += entry.Key + "=" + Uri.EscapeDataString(value) + "&";
            }

            return uri.TrimEnd('&');
        }
    }
}

namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text.RegularExpressions;
    using OpenIDClient.Messages;
    using Newtonsoft.Json.Linq;
    using System.Runtime.Serialization;

    public class Deserializer
    {
        public static void DeserializeFromDictionary(OIDClientSerializableMessage obj, Dictionary<string, object> data)
        {
            PropertyInfo[] properties = obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            foreach (PropertyInfo p in properties)
            {
                if (!OIDClientSerializableMessage.IsSupportedType(p.PropertyType))
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
                    p.SetValue(obj, propertyValue);
                }
                else if (p.PropertyType == typeof(ResponseType))
                {
                    if (data[propertyUnderscore].GetType() == typeof(ResponseType))
                    {
                        p.SetValue(obj, (ResponseType)data[propertyUnderscore]);
                    }
                    else
                    {
                        switch (data[propertyUnderscore].ToString())
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
                else if (p.PropertyType == typeof(List<string>))
                {
                    List<string> propertyValue = new List<string>();
                    if (data[propertyUnderscore].GetType() == typeof(string))
                    {
                        propertyValue.Add((string)data[propertyUnderscore]);
                    }
                    else
                    {
                        dynamic arrayData = data[propertyUnderscore];
                        foreach (string val in arrayData)
                        {
                            propertyValue.Add(val);
                        }
                    }

                    p.SetValue(obj, propertyValue);
                }
                else if (p.PropertyType == typeof(List<ResponseType>))
                {
                    List<ResponseType> propertyValue = new List<ResponseType>();
                    if (data[propertyUnderscore].GetType() == typeof(ResponseType))
                    {
                        propertyValue.Add((ResponseType)data[propertyUnderscore]);
                    }
                    else if (data[propertyUnderscore].GetType() == typeof(string))
                    {
                        switch (data[propertyUnderscore].ToString())
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
                    else if (data[propertyUnderscore].GetType() == typeof(List<ResponseType>))
                    {
                        List<ResponseType> arrayData = (List<ResponseType>) data[propertyUnderscore];
                        foreach (ResponseType val in arrayData)
                        {
                            propertyValue.Add(val);
                        }
                    }
                    else
                    {
                        JArray arrayData = (JArray)data[propertyUnderscore];
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
                else if (p.PropertyType == typeof(Dictionary<string, object>))
                {
                    Dictionary<string, object>propertyValue = (Dictionary<string, object>)data[propertyUnderscore];
                    p.SetValue(obj, propertyValue);
                }
                else if (p.PropertyType == typeof(DateTime))
                {
                    long dataLong = long.Parse(string.Empty + data[propertyUnderscore]);
                    DateTime propertyValue = DateTime.MaxValue;
                    if (dataLong != 0)
                    {
                        propertyValue = SecondsUtcToDateTime(dataLong);
                    }

                    p.SetValue(obj, propertyValue);
                }
                else if (p.PropertyType == typeof(bool))
                {
                    bool propertyValue = bool.Parse(string.Empty + data[propertyUnderscore]);
                    p.SetValue(obj, propertyValue);
                }
                else if (p.PropertyType == typeof(int))
                {
                    int propertyValue = int.Parse(string.Empty + data[propertyUnderscore]);
                    p.SetValue(obj, propertyValue);
                }
                else if (typeof(OIDClientSerializableMessage).IsAssignableFrom(p.PropertyType))
                {
                    OIDClientSerializableMessage propertyValue = (OIDClientSerializableMessage) Activator.CreateInstance(p.PropertyType);
                    JObject curObj = (JObject)data[propertyUnderscore];
                    propertyValue.DeserializeFromDictionary(curObj.ToObject<Dictionary<string, object>>());
                    p.SetValue(obj, propertyValue);
                }
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
    }
}

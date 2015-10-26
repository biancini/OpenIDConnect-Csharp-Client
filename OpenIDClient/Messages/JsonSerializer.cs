namespace OpenIDClient
{
    using System.Web.Script.Serialization;

    /// <summary>
    /// JSON Serializer using JavaScriptSerializer
    /// </summary>
    public static class JsonSerializer
    {
        private static readonly JavaScriptSerializer serializer = new JavaScriptSerializer();

        /// <summary>
        /// Serialize an object to JSON string
        /// </summary>
        /// <param name="obj">object</param>
        /// <returns>JSON string</returns>
        public static string Serialize(object obj)
        {
            return serializer.Serialize(obj);
        }

        /// <summary>
        /// Deserialize a JSON string to typed object.
        /// </summary>
        /// <typeparam name="T">type of object</typeparam>
        /// <param name="json">JSON string</param>
        /// <returns>typed object</returns>
        public static T Deserialize<T>(string json)
        {
            return serializer.Deserialize<T>(json);
        }
    }
}
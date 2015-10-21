namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public static class Base64UrlEncoder
    {
        /// <summary>
        /// Base64 URL encode message.
        /// </summary>
        /// <param name="input">The string of the message to be encoded.</param>
        /// <returns>The Base64 URL encoded string representing the message.</returns>
        public static string EncodeString(string input)
        {
            byte[] bytes = UTF8Encoding.UTF8.GetBytes(input);
            return EncodeBytes(bytes);
        }

        /// <summary>
        /// Base64 URL encode message.
        /// </summary>
        /// <param name="input">The byte array of the message to be encoded.</param>
        /// <returns>The Base64 URL encoded string representing the message.</returns>
        public static string EncodeBytes(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        /// <summary>
        /// Base64 URL decode message.
        /// </summary>
        /// <param name="input">The string representing the message to be decoded.</param>
        /// <returns>The string of the Base64 URL dencoded message.</returns>
        public static string DecodeString(string input)
        {
            byte[] bytes = DecodeBytes(input);
            return UTF8Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Base64 URL decode message.
        /// </summary>
        /// <param name="input">The string representing the message to be decoded.</param>
        /// <returns>The byte array of the Base64 URL dencoded message.</returns>
        public static byte[] DecodeBytes(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            // Pad with trailing '='s
            switch (output.Length % 4) 
            {
                case 0:
                    // No pad chars in this case
                    break; 
                case 2:
                    // Two pad chars
                    output += "==";
                    break; 
                case 3:
                    // One pad char
                    output += "=";
                    break;  
                default:
                    throw new Exception("Illegal base64url string!");
            }

            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}

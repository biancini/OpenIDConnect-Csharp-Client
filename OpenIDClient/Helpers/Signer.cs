using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Jose;

namespace OpenIDClient.Helpers
{
    public static class Signer
    {
        private static Dictionary<string, IJwsAlgorithm> HashAlgorithms = new Dictionary<string, IJwsAlgorithm>
        {
            {"none", new Plaintext()},
            {"HS256", new HmacUsingSha("SHA256")},
            {"HS384", new HmacUsingSha("SHA384")},
            {"HS512", new HmacUsingSha("SHA512")},

            {"RS256", new RsaUsingSha("SHA256")},
            {"RS384", new RsaUsingSha("SHA384")},
            {"RS512", new RsaUsingSha("SHA512")},

            {"ES256", new EcdsaUsingSha(256)},
            {"ES384", new EcdsaUsingSha(384)},
            {"ES512", new EcdsaUsingSha(521)}
        };

        /// <summary>
        /// Method that signs a string with a specific algorithm and key.
        /// </summary>
        /// <param name="Payload">The string to sign.</param>
        /// <param name="Algorithm">The algorithm to use for signing.</param>
        /// <param name="Key">The key to use for signing.</param>
        /// <returns>The bytes array signed message.</returns>
        public static byte[] Sign(string Payload, string Algorithm, object Key)
        {
            var bytesToSign = Encoding.UTF8.GetBytes(Payload);
            return HashAlgorithms[Algorithm].Sign(bytesToSign, Key);
        }
    }
}

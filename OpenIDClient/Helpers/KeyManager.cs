namespace OpenIDClient
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Net;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using OpenIDClient.Messages;

    public class KeyManager
    {
        /// <summary>
        /// Obtain the JWKS object describing certificates used by this RP for signing and encoding.
        /// </summary>
        /// <param name="EncodingCert">Certificate to be used for encoding.</param>
        /// <param name="SigningCert">Certificate to be used for signing.</param>
        /// <returns>The JWKS object with the keys of the RP.</returns>
        public static Dictionary<string, object> GetKeysJwks(X509Certificate2 EncodingCert, X509Certificate2 SigningCert)
        {
            return GetKeysJwks(new List<X509Certificate2>() { EncodingCert }, new List<X509Certificate2>() { SigningCert });
        }

        /// <summary>
        /// Method that permits to get a OIDCKey object representing a security key
        /// </summary>
        /// <param name="certificate">The certificate to use to create the key</param>
        /// <param name="keyType">The type of the key</param>
        /// <param name="use">The use of the mey ("sig" or "enc")</param>
        /// <param name="uniqueName">The unique name of he key in the keystore</param>
        /// <returns></returns>
        public static OIDCKey GetOIDCKey(X509Certificate2 certificate, string keyType, string use, string uniqueName = null)
        {
            RSACryptoServiceProvider rsa = certificate.PrivateKey as RSACryptoServiceProvider;
            RSAParameters par = rsa.ExportParameters(true);

            byte[] key = certificate.GetPublicKey();
            OIDCKey curCert = new OIDCKey();
            curCert.Use = use;
            curCert.N = Base64UrlEncoder.EncodeBytes(par.Modulus);
            curCert.E = Base64UrlEncoder.EncodeBytes(par.Exponent);
            curCert.D = Base64UrlEncoder.EncodeBytes(par.D);
            curCert.Q = Base64UrlEncoder.EncodeBytes(par.Q);
            curCert.Kty = keyType;
            curCert.Kid = uniqueName;
            return curCert;
        }

        /// <summary>
        /// Obtain the JWKS object describing certificates used by this RP for signing and encoding.
        /// </summary>
        /// <param name="EncodingCerts">List of certificates to be used for encoding.</param>
        /// <param name="SigningCerts">List of certificates to be used for signing.</param>
        /// <returns>The JWKS object with the keys of the RP.</returns>
        public static Dictionary<string, object> GetKeysJwks(List<X509Certificate2> EncodingCerts, List<X509Certificate2> SigningCerts)
        {
            List<Dictionary<string, object>> keys = new List<Dictionary<string, object>>();

            int countEnc = 1;
            foreach (X509Certificate2 certificate in EncodingCerts)
            {
                OIDCKey curCert = GetOIDCKey(certificate, "RSA", "enc", "Encoding Certificate " + countEnc);
                countEnc++;
                keys.Add(curCert.SerializeToDictionary());
            }

            int countSign = 1;
            foreach (X509Certificate2 certificate in SigningCerts)
            {
                OIDCKey curCert = GetOIDCKey(certificate, "RSA", "sig", "Signing Certificate " + countEnc);
                countSign++;
                keys.Add(curCert.SerializeToDictionary());
            }

            Dictionary<string, object> keysDict = new Dictionary<string, object>();
            keysDict.Add("keys", keys);
            return keysDict;
        }
    }
}

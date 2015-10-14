using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using OpenIDClient.Messages;
using JWT;

namespace OpenIDClient
{
    /// <summary>
    /// Class implementing an OpenIDConnect Relying Party and that could be used to authenticat users
    /// with OpenID OP.
    /// </summary>
    public class OpenIdRelyingParty
    {
        /// <summary>
        /// Method generating a random string with numbers or letters.
        /// </summary>
        /// <param name="length">The length of the string to generate.</param>
        /// <returns>The random string generated.</returns>
        public string RandomString(int length = 16)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        /// <summary>
        /// Method that performs an HTTP GET and returns the Json deserialization
        /// of the content returned from the call.
        /// </summary>
        /// <param name="webRequest">The WebRequest object to be used for the call.</param>
        /// <returns>Json deserialization of the content returned from the call.</returns>
        public static Dictionary<string,object> GetUrlContent(WebRequest webRequest)
        {
            Stream content = webRequest.GetResponse().GetResponseStream();
            string returnedText = new StreamReader(content).ReadToEnd();
            IJsonSerializer JsonSerializer = new DefaultJsonSerializer();
            return JsonSerializer.Deserialize<Dictionary<string, object>>(returnedText);
        }

        /// <summary>
        /// Method that performs an HTTP POST and returns the Json deserialization
        /// of the content returned from the call.
        /// </summary>
        /// <param name="webRequest">The WebRequest object to be used for the call.</param>
        /// <param name="message">The message to be passed as content of the call.</param>
        /// <param name="json">A flag indicating whether the message has a Json format or not.
        /// In the first case the message is posted as a serialization of the Json.
        /// In the second case the messge is serialized to query string.</param>
        /// <returns>Json deserialization of the content returned from the call.</returns>
        public Dictionary<string, object> PostUrlContent(WebRequest webRequest, OIDClientSerializableMessage message, bool json = false)
        {
            webRequest.Method = "POST";

            string postData = "";
            if (message != null)
            {
                if (json)
                {
                    postData = message.serializeToJsonString();
                }
                else
                {
                    postData = message.serializeToQueryString();
                }
            }
            byte[] postBytes = Encoding.UTF8.GetBytes(postData);

            webRequest.ContentType = "application/x-www-form-urlencoded";
            webRequest.ContentLength = postBytes.Length;

            Stream postStream = webRequest.GetRequestStream();
            postStream.Write(postBytes, 0, postBytes.Length);
            postStream.Close();

            HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse();

            StreamReader rdr = new StreamReader(response.GetResponseStream());
            IJsonSerializer JsonSerializer = new DefaultJsonSerializer();
            return JsonSerializer.Deserialize<Dictionary<string, object>>(rdr.ReadToEnd());
        }

        private string ObtainIssuer(string hostname, string resource)
        {
            string query = "/.well-known/webfinger?resource=" + resource + "&rel=http://openid.net/specs/connect/1.0/issuer";

            WebRequest webRequest = WebRequest.Create(hostname + query);
            Dictionary<string, object> o = GetUrlContent(webRequest);
            if (DateTime.Parse(o["expires"] as string) < DateTime.UtcNow - new TimeSpan(0, 10, 0))
            {
                throw new OIDCException("Claims expired on " + o["expires"]);
            }

            if ((string)o["subject"] != resource)
            {
                throw new OIDCException("Claims released for a different subject.");
            }

            string issuer = null;
            ArrayList links = (ArrayList)o["links"];
            foreach (Dictionary<string, object> link in links)
            {
                if (link["rel"] as string == "http://openid.net/specs/connect/1.0/issuer")
                {
                    issuer = link["href"] as string;
                }
            }

            if (issuer == null)
            {
                throw new OIDCException("No issuer found in claims returned.");
            }
            return issuer;
        }

        /// <summary>
        /// Method that obtains the issuer string from the OP via a webfinger call
        /// starting from a username with the email format.
        /// </summary>
        /// <param name="email">The username to be used in the query to obtain the issuer.</param>
        /// <param name="hostname">(optional) The hostname of the OP to be queried, if not
        /// specified the hostname will be retrieved from the email address.</param>
        /// <returns>A string with the issuer string.</returns>
        /// <exception cref="OpenIDClient.OIDCException">Thrown when the passed email is not
        /// valid or if the returned message from server is not valid.</exception>
        public string ObtainIssuerFromEmail(string email, string hostname = null)
        {
            Regex regex = new Regex(@"^([\w\.\-]+)@([\w\-]+)(\.([\w\-]+))*((\.(\w){2,3})+)?$");
            Match match = regex.Match(email);
            if (!match.Success)
            {
                throw new OIDCException("Wrong format for email passed as parameter.");
            }
            if (hostname == null)
            {
                hostname = "https://" + email.Split('@')[1];
            }
            return ObtainIssuer(hostname, "acct:" + email);
        }

        /// <summary>
        /// Method that obtains the issuer string from the OP via a webfinger call
        /// starting from a username with the URL format.
        /// </summary>
        /// <param name="url">The URL to be used in the query to obtain the issuer.</param>
        /// <param name="hostname">(optional) The hostname of the OP to be queried, if not
        /// specified the hostname will be retrieved from the email address.</param>
        /// <returns>A string with the issuer string.</returns>
        /// <exception cref="OpenIDClient.OIDCException">Thrown when the passed email is not
        /// valid or if the returned message from server is not valid.</exception>
        public string ObtainIssuerFromURL(string url, string hostname = null)
        {
            Regex regex = new Regex(@"^https://([\w+?\.\w+])+([a-zA-Z0-9\~\!\@\#\$\%\^\&\*\(\)_\-\=\+\\\/\?\.\:\;\'\,]*)?$", RegexOptions.IgnoreCase);
            Match match = regex.Match(url);
            if (!match.Success)
            {
                throw new OIDCException("Wrong format for url passed as parameter.");
            }
            if (hostname == null)
            {
                hostname = url;
                for (int i = url.Length - 1; i >= 0; i--)
                {
                    if (url[i] == '/')
                    {
                        hostname = url;
                        break;
                    }
                }
            }
            return ObtainIssuer(hostname, url);
        }

        /// <summary>
        /// Method that queries the OP server to obtain the OpenID configuration.
        /// </summary>
        /// <param name="hostname">The hostname of the OP to be queried.</param>
        /// <param name="expectedIssuer">(optional) the issuer expected from the OP configuration.
        /// This information can come, for instance, from a previous issuer discovery process
        /// via webfinger.</param>
        /// <returns>An oject describing all relevant properties of the OP.</returns>
        /// <exception cref="OpenIDClient.OIDCException">Thrown when the returned message from server
        /// is not valid or if wrong issuer is found in the answer.</exception>
        public OIDCProviderMetadata ObtainProviderInformation(string hostname, string expectedIssuer = null)
        {
            string query = "/.well-known/openid-configuration";
            WebRequest webRequest = WebRequest.Create(hostname + query);
            Dictionary<string,object> o = GetUrlContent(webRequest);
            OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(o);

            if (expectedIssuer != null && !expectedIssuer.Equals(providerMetadata.Issuer))
            {
                throw new OIDCException("Wrong issuer, discarding configuration");
            }

            return providerMetadata;
        }

        /// <summary>
        /// Method that performs a dynamic client registration with the OP server.
        /// </summary>
        /// <param name="RegistrationEndpoint">The URL of the OP describing the registration endpoint.</param>
        /// <param name="clientMetadata">The OIDCClientInformation object describing the client information to
        /// be submitted to the OP for registration.</param>
        /// <param name="TokenEndpointAuthMethod">(optional) the endpoint authentication method used to
        /// authenticate the client with the OP sever (if not specified using "client_secret_basic".</param>
        /// <returns>An oject describing all client information as returned by the OP server after
        /// registration.</returns>
        /// <exception cref="OpenIDClient.OIDCException">Thrown when an error occurs while registering
        /// the client with the OP.</exception>
        public OIDCClientInformation RegisterClient(string RegistrationEndpoint, OIDCClientInformation clientMetadata, string TokenEndpointAuthMethod = "client_secret_basic")
        {
            // Make registration request
            OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest();
            registrationRequest.ApplicationType = clientMetadata.ApplicationType;
            registrationRequest.RedirectUris = clientMetadata.RedirectUris;
            registrationRequest.ResponseTypes = clientMetadata.ResponseTypes;
            registrationRequest.JwksUri = clientMetadata.JwksUri;
            registrationRequest.TokenEndpointAuthMethod = TokenEndpointAuthMethod;

            // Check error and store client information from OP
            WebRequest request = WebRequest.Create(RegistrationEndpoint);
            Dictionary<string,object> returnedJson = PostUrlContent(request, registrationRequest, true);
            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                throw new OIDCException("Error while registering client: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCClientInformation clientInformation = new OIDCClientInformation();
            clientInformation.deserializeFromDynamic(returnedJson);
            return clientInformation;
        }

        /// <summary>
        /// Obtain the JWKS object describing certificates used by this RP for signing and encoding.
        /// </summary>
        /// <param name="EncodingCert">Certificate to be used for encoding.</param>
        /// <param name="SigningCert">Certificate to be used for signing.</param>
        /// <returns>The JWKS object with the keys of the RP.</returns>
        public static Dictionary<string, object> GetKeysJwks(X509Certificate EncodingCert, X509Certificate SigningCert)
        {
            return GetKeysJwks(new List<X509Certificate>() { EncodingCert }, new List<X509Certificate>() { SigningCert });
        }

        /// <summary>
        /// Obtain the JWKS object describing certificates used by this RP for signing and encoding.
        /// </summary>
        /// <param name="EncodingCerts">List of certificates to be used for encoding.</param>
        /// <param name="SigningCerts">List of certificates to be used for signing.</param>
        /// <returns>The JWKS object with the keys of the RP.</returns>
        public static Dictionary<string, object> GetKeysJwks(List<X509Certificate> EncodingCerts, List<X509Certificate> SigningCerts)
        {
            List<OIDCKey> keys = new List<OIDCKey>();

            int countEnc = 1;
            foreach (X509Certificate certificate in EncodingCerts)
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(certificate.GetRawCertDataString());
                OIDCKey curCert = new OIDCKey();
                curCert.Use = "enc";
                curCert.N = Convert.ToBase64String(plainTextBytes);
                curCert.E = "AQAB";
                curCert.Kty = "RSA";
                curCert.Kid = "Encoding Certificate " + countEnc;

                countEnc++;
                keys.Add(curCert);
            }

            int countSign = 1;
            foreach (X509Certificate certificate in SigningCerts)
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(certificate.GetRawCertDataString());
                OIDCKey curCert = new OIDCKey();
                curCert.Use = "enc";
                curCert.N = Convert.ToBase64String(plainTextBytes);
                curCert.E = "AQAB";
                curCert.Kty = "RSA";
                curCert.Kid = "Signing Certificate " + countEnc;

                countSign++;
                keys.Add(curCert);
            }

            Dictionary<string, object> keysDict = new Dictionary<string, object>();
            keysDict.Add("keys", keys);
            return keysDict;
        }

        public OIDCAuthCodeResponseMessage ParseAuthCodeResponse(string queryString, string scope = null, string state = null)
        {
            OIDCAuthCodeResponseMessage responseMessage = new OIDCAuthCodeResponseMessage();
            try
            {
                responseMessage.deserializeFromQueryString(queryString);
            }
            catch (OIDCException)
            {
                OIDCResponseError error = new OIDCResponseError();
                error.deserializeFromQueryString(queryString);
                throw new OIDCException("Error while parsing authorization response: " + error.Error + "\n" + error.ErrorDescription);
            }

            if (scope != null && responseMessage.Scope != null && responseMessage.Scope != scope)
            {
                throw new OIDCException("Error with authentication answer, wrong scope.");
            }

            if (state != null && responseMessage.State != state)
            {
                throw new OIDCException("Error with authentication answer, wrong state.");
            }

            return responseMessage;
        }

        public OIDCAuthImplicitResponseMessage ParseAuthImplicitResponse(string queryString, string scope = null, string state = null)
        {
            OIDCAuthImplicitResponseMessage responseMessage = new OIDCAuthImplicitResponseMessage();
            try
            {
                responseMessage.deserializeFromQueryString(queryString);
            }
            catch (OIDCException)
            {
                OIDCResponseError error = new OIDCResponseError();
                error.deserializeFromQueryString(queryString);
                throw new OIDCException("Error while parsing authorization response: " + error.Error + "\n" + error.ErrorDescription);
            }

            if (state != null && responseMessage.State != state)
            {
                throw new OIDCException("Error with authentication answer, wrong state.");
            }

            return responseMessage;
        }

        private OIDCClientSecretJWT AddClientAuthenticatedToRequest(ref WebRequest request, ref OIDCAuthenticatedMessage requestMessage, string grantType, OIDCClientInformation clientInformation)
        {
            OIDCClientSecretJWT tokenData = null;
            switch (grantType)
            {
                case "client_secret_basic":
                    string basic = clientInformation.ClientId + ":" + clientInformation.ClientSecret;
                    request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(basic)));
                    break;
                case "client_secret_post":
                    requestMessage.ClientId = clientInformation.ClientId;
                    requestMessage.ClientSecret = clientInformation.ClientSecret;
                    break;
                case "client_secret_jwt":
                case "private_key_jwt":
                    // TODO understand how to sign JWT
                    tokenData = new OIDCClientSecretJWT();
                    tokenData.Iss = clientInformation.ClientId;
                    tokenData.Sub = clientInformation.ClientId;
                    tokenData.Aud = request.RequestUri.ToString();
                    if (tokenData.Aud.Contains("?"))
                    {
                        tokenData.Aud = tokenData.Aud.Substring(0, tokenData.Aud.IndexOf("?"));
                    }
                    tokenData.Jti = RandomString();
                    tokenData.Exp = DateTime.Now;
                    tokenData.Iat = DateTime.Now - new TimeSpan(0, 10, 0);
                    requestMessage.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                    requestMessage.ClientAssertion = JsonWebToken.Encode(tokenData, Encoding.UTF8.GetBytes(clientInformation.ClientSecret), JwtHashAlgorithm.HS256);
                    break;
                default: // case "none"
                    break;
            }

            return tokenData;
        }

        public OIDCTokenResponseMessage SubmitTokenRequest(string url, OIDCTokenRequestMessage tokenRequestMessage, OIDCClientInformation clientInformation)
        {
            WebRequest request = WebRequest.Create(url);
            OIDCAuthenticatedMessage message = tokenRequestMessage as OIDCAuthenticatedMessage;
            string grantType = clientInformation.TokenEndpointAuthMethod;
            OIDCClientSecretJWT tokenData = AddClientAuthenticatedToRequest(ref request, ref message, grantType, clientInformation);
            Dictionary<string, object> returnedJson = PostUrlContent(request, message);

            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                error.deserializeFromDynamic(returnedJson);
                throw new OIDCException("Error while registering client: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCTokenResponseMessage tokenResponse = new OIDCTokenResponseMessage();
            tokenResponse.deserializeFromDynamic(returnedJson);
            return tokenResponse;
        }

        public OIDCUserInfoResponseMessage GetUserInfo(string url, OIDCUserInfoRequestMessage userInfoRequestMessage, string accessToken)
        {
            WebRequest request = WebRequest.Create(url);
            request.Headers.Add("Authorization", "Bearer " + accessToken);
            Dictionary<string, object> returnedJson = PostUrlContent(request, userInfoRequestMessage);

            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                error.deserializeFromDynamic(returnedJson);
                throw new OIDCException("Error while asking for user info: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCUserInfoResponseMessage userInfoResponse = new OIDCUserInfoResponseMessage();
            userInfoResponse.deserializeFromDynamic(returnedJson);
            return userInfoResponse;
        }

        public void ValidateIdToken(OIDCIdToken idToken, OIDCClientInformation clientInformation, OIDCProviderMetadata providerMetadata, string nonce)
        {
            if (idToken.Iss.Trim('/') != providerMetadata.Issuer.Trim('/'))
            {
                throw new OIDCException("Wrong issuer for the token.");
            }
            
            if (!idToken.Aud.Contains(clientInformation.ClientId))
            {
                throw new OIDCException("Intended audience of the token does not include client_id.");
            }

            if (idToken.Aud.Count > 1 && idToken.Azp == null)
            {
                throw new OIDCException("Multiple audience but no authorized party specified.");
            }

            if (idToken.Azp != null && idToken.Azp != clientInformation.ClientId)
            {
                throw new OIDCException("The authorized party does not match client_id.");
            }

            if (idToken.Exp < DateTime.UtcNow - new TimeSpan(0, 10, 0))
            {
                throw new OIDCException("The token is expired.");
            }

            if (idToken.Iat < DateTime.Now - new TimeSpan(24, 0, 0))
            {
                throw new OIDCException("The token has ben issued more than a day ago.");
            }

            if (nonce != null && idToken.Nonce != nonce)
            {
                throw new OIDCException("Wrong nonce value in token.");
            }
        }
    }

    public class OIDCException : Exception
    {
        public OIDCException(string message) : base(message)
        {
        }
    }
}

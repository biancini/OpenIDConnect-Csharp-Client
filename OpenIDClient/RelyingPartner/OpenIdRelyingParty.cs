namespace OpenIDClient
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using OpenIDClient.Messages;
    using Newtonsoft.Json.Linq;
    using Jose;

    /// <summary>
    /// Class implementing an OpenIDConnect Relying Party and that could be used to authenticat users
    /// with OpenID OP.
    /// </summary>
    public class OpenIdRelyingParty
    {
        /// <summary>
        /// Method that sends authentication request to the OP.
        /// </summary>
        /// <param name="AuthenticateUrl">The URL to be used for the authentication request.</param>
        /// <param name="RequestMessage">The reuqest message to be sent to the OP.</param>
        /// <param name="Certificate">The certificate to be used, in case of a self-issued authentication.</param>
        /// <returns>The authentication response from the OP.</returns>
        public OIDCAuthImplicitResponseMessage Authenticate(string AuthenticateUrl, OIDCAuthorizationRequestMessage RequestMessage, X509Certificate2 Certificate = null)
        {
            if (new Uri(AuthenticateUrl).Scheme == "openid")
            {
                // we are dealing with a Self-Issued OpenID provider
                Dictionary<string, object> response = PerformSelfIssuedAuthentication(RequestMessage, Certificate);
                OIDCAuthImplicitResponseMessage responseMessage = new OIDCAuthImplicitResponseMessage();
                responseMessage.DeserializeFromDictionary(response);
                return responseMessage;
            }
            else
            {
                string login_url = AuthenticateUrl + "?" + RequestMessage.SerializeToQueryString();
                WebOperations.GetUrlContent(WebRequest.Create(login_url));
                return null;
            }
        }

        private Dictionary<string, object> PerformSelfIssuedAuthentication(OIDCAuthorizationRequestMessage requestMessage, X509Certificate2 certificate)
        {
            OIDCIdToken idToken = new OIDCIdToken();
            idToken.Iss = "https://self-issued.me";
            idToken.Sub = Convert.ToBase64String(Encoding.UTF8.GetBytes(certificate.Thumbprint));
            idToken.Aud = new List<string>() { requestMessage.RedirectUri };
            idToken.Nonce = requestMessage.Nonce;
            idToken.Exp = DateTime.MaxValue;
            idToken.Iat = DateTime.MaxValue;
            idToken.SubJkw = KeyManager.GetOIDCKey(certificate, "RSA", "AQAB", "sig");

            if (requestMessage.Scope.Contains("profile"))
            {
                idToken.GivenName = "Myself";
                idToken.FamilyName = "User";
                idToken.Name = idToken.GivenName + " " + idToken.FamilyName;
            }

            if (requestMessage.Scope.Contains("email"))
            {
                idToken.Email = "me@self-issued.me";
            }

            if (requestMessage.Scope.Contains("address"))
            {
                idToken.Address = new OIDCAddress();
                idToken.Address.Country = "Italy";
                idToken.Address.PostalCode = "20100";
                idToken.Address.StreetAddress = "Via Test, 1";
                idToken.Address.Locality = "Milano";
            }

            if (requestMessage.Scope.Contains("phone"))
            {
                idToken.PhoneNumber = "0";
            }

            idToken.Validate();

            Dictionary<string, object> responseMessage = new Dictionary<string, object>();
            responseMessage["id_token"] = JWT.Encode(idToken.SerializeToJsonString(), null, JwsAlgorithm.none);
            responseMessage["state"] = requestMessage.State;

            return responseMessage;
        }
        
        private string ObtainIssuer(string hostname, string resource)
        {
            string query = "/.well-known/webfinger?resource=" + resource + "&rel=http://openid.net/specs/connect/1.0/issuer";

            WebRequest webRequest = WebRequest.Create(hostname + query);
            Dictionary<string, object> o = WebOperations.GetUrlContent(webRequest);
            if ((DateTime)o["expires"] < DateTime.UtcNow - new TimeSpan(0, 10, 0))
            {
                throw new OIDCException("Claims expired on " + o["expires"]);
            }

            if ((string)o["subject"] != resource)
            {
                throw new OIDCException("Claims released for a different subject.");
            }

            string issuer = null;
            JArray links = (JArray)o["links"];
            foreach (JObject link in links)
            {
                Dictionary<string, object> dic = link.ToObject<Dictionary<string, object>>();
                if (dic["rel"] as string == "http://openid.net/specs/connect/1.0/issuer")
                {
                    issuer = dic["href"] as string;
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
            string issuerHostname = hostname;
            Regex regex = new Regex(@"^([\w\.\-]+)@([\w\-]+)(\.([\w\-]+))*((\.(\w){2,3})+)?$");
            Match match = regex.Match(email);
            if (!match.Success)
            {
                throw new OIDCException("Wrong format for email passed as parameter.");
            }
            if (issuerHostname == null)
            {
                issuerHostname = "https://" + email.Split('@')[1];
            }
            return ObtainIssuer(issuerHostname, "acct:" + email);
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
            string issuerHostname = hostname;
            Regex regex = new Regex(@"^https://([\w+?\.\w+])+([a-zA-Z0-9\~\!\@\#\$\%\^\&\*\(\)_\-\=\+\\\/\?\.\:\;\'\,]*)?$", RegexOptions.IgnoreCase);
            Match match = regex.Match(url);
            if (!match.Success)
            {
                throw new OIDCException("Wrong format for url passed as parameter.");
            }
            if (issuerHostname == null)
            {
                issuerHostname = url.TrimEnd('/');
            }
            return ObtainIssuer(issuerHostname, url);
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
            Dictionary<string,object> o = WebOperations.GetUrlContent(webRequest);
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
            Dictionary<string, object> data = clientMetadata.SerializeToDictionary();
            OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest();
            registrationRequest.DeserializeFromDictionary(data);

            // Check error and store client information from OP
            WebRequest request = WebRequest.Create(RegistrationEndpoint);
            Dictionary<string, object> returnedJson = WebOperations.PostUrlContent(request, registrationRequest, true);
            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                throw new OIDCException("Error while registering client: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCClientInformation clientInformation = new OIDCClientInformation();
            clientInformation.DeserializeFromDictionary(returnedJson);
            return clientInformation;
        }

        /// <summary>
        /// Method to perform third party initiated login.
        /// </summary>
        /// <param name="queryString">The query string representation of the authentication request</param>
        /// <param name="authEndpoint">The OP authorization endpoint</param>
        public void ThirdPartyInitiatedLogin(OIDCAuthorizationRequestMessage requestMessage, string authEndpoint)
        {
            string login_url = authEndpoint + "?" + requestMessage.SerializeToQueryString();
            WebOperations.GetUrlContent(WebRequest.Create(login_url));
        }

        /// <summary>
        /// Method called toparse an authentication code response from OP.
        /// </summary>
        /// <param name="queryString">The string reprsenting the authentication response provided
        /// by the OP.</param>
        /// <param name="scope">(optional) Eventual scope used for the call to be used for verification.</param>
        /// <param name="state">(optional) Eventual state used for the call to be used for verification.</param>
        /// <returns>A validated message containing answer frop OP.</returns>
        public OIDCAuthCodeResponseMessage ParseAuthCodeResponse(string queryString, List<string> scope = null, string state = null)
        {
            OIDCAuthCodeResponseMessage responseMessage = new OIDCAuthCodeResponseMessage();
            try
            {
                responseMessage.DeserializeFromQueryString(queryString);
            }
            catch (OIDCException)
            {
                OIDCResponseError error = new OIDCResponseError();
                error.DeserializeFromQueryString(queryString);
                throw new OIDCException("Error while parsing authorization response: " + error.Error + "\n" + error.ErrorDescription);
            }

            if (scope != null && responseMessage.Scope != null && responseMessage.Scope.Equals(scope))
            {
                throw new OIDCException("Error with authentication answer, wrong scope.");
            }

            if (state != null && responseMessage.State != state)
            {
                throw new OIDCException("Error with authentication answer, wrong state.");
            }

            return responseMessage;
        }

        /// <summary>
        /// Method called toparse an authentication implicit response from OP.
        /// </summary>
        /// <param name="queryString">The string reprsenting the authentication response provided
        /// by the OP.</param>
        /// <param name="scope">(optional) Eventual scope used for the call to be used for verification.</param>
        /// <param name="state">(optional) Eventual state used for the call to be used for verification.</param>
        /// <returns>A validated message containing answer frop OP.</returns>
        public OIDCAuthImplicitResponseMessage ParseAuthImplicitResponse(string queryString, List<string> scope = null, string state = null)
        {
            OIDCAuthImplicitResponseMessage responseMessage = new OIDCAuthImplicitResponseMessage();
            try
            {
                responseMessage.DeserializeFromQueryString(queryString);
            }
            catch (OIDCException)
            {
                OIDCResponseError error = new OIDCResponseError();
                error.DeserializeFromQueryString(queryString);
                throw new OIDCException("Error while parsing authorization response: " + error.Error + "\n" + error.ErrorDescription);
            }

            if (state != null && responseMessage.State != state)
            {
                throw new OIDCException("Error with authentication answer, wrong state.");
            }

            return responseMessage;
        }

        private OIDCClientSecretJWT AddClientAuthenticatedToRequest(ref WebRequest request, ref OIDCAuthenticatedMessage requestMessage, string grantType, OIDCClientInformation clientInformation, byte[] privateKey)
        {
            OIDCClientSecretJWT tokenData = null;
            byte[] encKey = null;
            switch (grantType)
            {
                case "client_secret_basic":
                    string basic = clientInformation.ClientId + ":" + clientInformation.ClientSecret;
                    basic = Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(basic));
                    request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(basic)));
                    break;
                case "client_secret_post":
                    requestMessage.ClientId = clientInformation.ClientId;
                    requestMessage.ClientSecret = clientInformation.ClientSecret;
                    break;
                case "client_secret_jwt":
                    encKey = Encoding.UTF8.GetBytes(clientInformation.ClientSecret);
                    break;
                case "private_key_jwt":
                    encKey = privateKey;
                    break;
                default: // case "none"
                    break;
            }

            // If client_secret_jwt or private_key_jwt pass a JWT bearer token with the
            // specified key for encryption.
            if (encKey != null)
            {
                tokenData = new OIDCClientSecretJWT();
                tokenData.Iss = clientInformation.ClientId;
                tokenData.Sub = clientInformation.ClientId;
                tokenData.Aud = request.RequestUri.ToString();
                if (tokenData.Aud.Contains("?"))
                {
                    tokenData.Aud = tokenData.Aud.Substring(0, tokenData.Aud.IndexOf("?"));
                }
                tokenData.Jti = WebOperations.RandomString();
                tokenData.Exp = DateTime.Now;
                tokenData.Iat = DateTime.Now - new TimeSpan(0, 10, 0);
                requestMessage.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                requestMessage.ClientAssertion = JWT.Encode(tokenData, encKey, Jose.JwsAlgorithm.HS256);
            }

            return tokenData;
        }

        /// <summary>
        /// Method that submits a tokn request to the OP.
        /// </summary>
        /// <param name="url">The URL to be used where to send the request</param>
        /// <param name="tokenRequestMessage">The token request message</param>
        /// <param name="clientInformation">The client information obtained from the OP</param>
        /// <returns>Returns the token response obtained from the OP</returns>
        public OIDCTokenResponseMessage SubmitTokenRequest(string url, OIDCTokenRequestMessage tokenRequestMessage, OIDCClientInformation clientInformation, byte[] privateKey = null)
        {
            WebRequest request = WebRequest.Create(url);
            OIDCAuthenticatedMessage message = tokenRequestMessage as OIDCAuthenticatedMessage;
            string grantType = clientInformation.TokenEndpointAuthMethod;
            AddClientAuthenticatedToRequest(ref request, ref message, grantType, clientInformation, privateKey);
            Dictionary<string, object> returnedJson = WebOperations.PostUrlContent(request, message);

            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                error.DeserializeFromDictionary(returnedJson);
                throw new OIDCException("Error while registering client: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCTokenResponseMessage tokenResponse = new OIDCTokenResponseMessage();
            tokenResponse.DeserializeFromDictionary(returnedJson);
            return tokenResponse;
        }

        /// <summary>
        /// Get user information from the OP after user authentication
        /// </summary>
        /// <param name="url">The url to be used to retrieve user information</param>
        /// <param name="userInfoRequestMessage">The user info request message</param>
        /// <param name="accessToken">The access token obtain during authentication</param>
        /// <returns>The response message containing user information</returns>
        public OIDCUserInfoResponseMessage GetUserInfo(string url, OIDCUserInfoRequestMessage userInfoRequestMessage, string accessToken)
        {
            WebRequest request = WebRequest.Create(url);
            request.Headers.Add("Authorization", "Bearer " + accessToken);
            Dictionary<string, object> returnedJson = WebOperations.PostUrlContent(request, userInfoRequestMessage);

            if (returnedJson.Keys.Contains("error"))
            {
                OIDCResponseError error = new OIDCResponseError();
                error.DeserializeFromDictionary(returnedJson);
                throw new OIDCException("Error while asking for user info: " + error.Error + "\n" + error.ErrorDescription);
            }

            OIDCUserInfoResponseMessage userInfoResponse = new OIDCUserInfoResponseMessage();
            userInfoResponse.DeserializeFromDictionary(returnedJson);
            return userInfoResponse;
        }

        /// <summary>
        /// Method that validates the IdToken with specific rules
        /// </summary>
        /// <param name="idToken"></param>
        /// <param name="clientInformation"></param>
        /// <param name="providerMetadata"></param>
        /// <param name="nonce"></param>
        public void ValidateIdToken(OIDCIdToken idToken, OIDCClientInformation clientInformation, string Issuer, string Nonce)
        {
            if (idToken.Iss.Trim('/') != Issuer.Trim('/'))
            {
                throw new OIDCException("Wrong issuer for the token.");
            }
            
            if (Issuer != "https://self-issued.me" && !idToken.Aud.Contains(clientInformation.ClientId))
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

            if (Nonce != null && idToken.Nonce != Nonce)
            {
                throw new OIDCException("Wrong nonce value in token.");
            }
        }
    }
}

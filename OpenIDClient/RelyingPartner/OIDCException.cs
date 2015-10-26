namespace OpenIDClient
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;


    /// <summary>
    /// Class representing an exception in the library.
    /// </summary>
    public class OIDCException : Exception
    {
        /// <summary>
        /// Contructor with a message string.
        /// </summary>
        /// <param name="message">The message to be saved in the exception.</param>
        public OIDCException(string message)
            : base(message)
        {
        }
    }
}

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// Config collection of IdentityProviderElements.
    /// </summary>
    public class OpenIDProviderCollection : ConfigurationElementCollection, IEnumerable<OpenIDProviderElement>
    {
        /// <summary>
        /// Create new element of right type.
        /// </summary>
        /// <returns>IdentityProviderElement</returns>
        protected override ConfigurationElement CreateNewElement()
        {
            return new OpenIDProviderElement();
        }

        /// <summary>
        /// Get the name of an element.
        /// </summary>
        /// <param name="element">OpenIDProviderElement</param>
        /// <returns>element.Name</returns>
        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((OpenIDProviderElement)element).EntityId;
        }

        /// <summary>
        /// Register the configured identity providers in the dictionary of active idps.
        /// </summary>
        /// <param name="options">Current options.</param>
        public void RegisterOpenIDProviders(IOptions options)
        {
            if(options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            foreach(var opEntry in this)
            {
                options.OpenIDProviders[opEntry.EntityId] = opEntry;
            }
        }

        /// <summary>
        /// Get a strongly typed enumerator.
        /// </summary>
        /// <returns>Strongly typed enumerator.</returns>
        public new IEnumerator<OpenIDProviderElement> GetEnumerator()
        {
            return base.GetEnumerator().AsGeneric<OpenIDProviderElement>();
        }
    }
}

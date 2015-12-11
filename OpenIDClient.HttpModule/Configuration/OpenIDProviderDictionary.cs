using System;
using System.Collections.Generic;
using System.IdentityModel.Metadata;
using System.Linq;

namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// A thread safe wrapper around a dictionary for the openid providers.
    /// </summary>
    /// <remarks>
    /// First I thought about using a ConcurrentDictionary, but that does not maintain
    /// any order of the added objects. Since the first idp added becomes the default idp,
    /// the order must be preserved. And there has to be queuing semantics if the first idp
    /// is dynamically loaded from a federation and later removed. Locks are simple and
    /// this part of the code shouldn't be that performance sensitive.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1711:IdentifiersShouldNotHaveIncorrectSuffix", Justification="It works like dictionary, even though it doesn't implement the full interface.")]
    public class OpenIDProviderDictionary
    {
        private Dictionary<string, OpenIDProviderElement> dictionary =
            new Dictionary<string, OpenIDProviderElement>();

        /// <summary>
        /// Gets an idp from the entity id.
        /// </summary>
        /// <param name="entityId">entity Id to look up.</param>
        /// <returns>IdentityProvider</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1043:UseIntegralOrStringArgumentForIndexers")]
        public OpenIDProviderElement this[string entityId]
        {
            get
            {
                if(entityId == null)
                {
                    throw new ArgumentNullException(nameof(entityId));
                }

                lock(dictionary)
                {
                    try
                    {
                        return dictionary[entityId];
                    }
                    catch (KeyNotFoundException e)
                    {
                        throw new KeyNotFoundException(
                            "No OP with entity id \"" + entityId + "\" found.", e);
                    }
                }
            }
            set
            {
                lock (dictionary)
                {
                    dictionary[entityId] = value;
                }
            }
        }

        /// <summary>
        /// Add an OpenID provider to the collection..
        /// </summary>
        /// <param name="op">OpenID provider to add.</param>
        public void Add(OpenIDProviderElement op)
        {
            if(op == null)
            {
                throw new ArgumentNullException(nameof(op));
            }

            lock(dictionary)
            {
                dictionary.Add(op.EntityId, op);
            }
        }

        /// <summary>
        /// The default identity provider; i.e. the first registered of the currently known.
        /// </summary>
        public OpenIDProviderElement Default
        {
            get
            {
                return this[0];
            }
        }

        // Used by tests.
        internal OpenIDProviderElement this[int i]
        {
            get
            {
                lock(dictionary)
                {
                    return dictionary.Values.Skip(i).First();
                }
            }
        }

        /// <summary>
        /// Try to get the value of an idp with a given entity id.
        /// </summary>
        /// <param name="opEntityId">Entity id to search for.</param>
        /// <param name="op">The op, if found.</param>
        /// <returns>True if an idp with the given entity id was found.</returns>
        public bool TryGetValue(string opEntityId, out OpenIDProviderElement op)
        {
            lock (dictionary)
            {
                return dictionary.TryGetValue(opEntityId, out op);
            }
        }

        /// <summary>
        /// Checks if there are no known identity providers.
        /// </summary>
        public bool IsEmpty
        {
            get
            {
                lock (dictionary)
                {
                    return dictionary.Count == 0;
                }
            }
        }

        /// <summary>
        /// Removes the op with the given entity id, if present. If no such
        /// entity is found, nothing is done.
        /// </summary>
        /// <param name="op">EntityId of op to remove.</param>
        public void Remove(string op)
        {
            lock(dictionary)
            {
                dictionary.Remove(op);
            }
        }
    }
}

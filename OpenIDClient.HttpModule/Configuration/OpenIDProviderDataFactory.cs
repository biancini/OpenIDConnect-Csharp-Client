namespace OpenIDClient.HttpModule.Configuration
{
    using System;
    using System.Collections.Generic;
    using OpenIDClient.HttpModule.WebSso;

    public static class OpenIDProviderDataFactory
    {
        private static Dictionary<string, OpenIDProviderData> providers = new Dictionary<string, OpenIDProviderData>();

        public static OpenIDProviderData GetOpenIDProviderData(string entityId, OpenIDProviderElement opEntry, IRPOptions options)
        {
            lock (providers)
            {
                if (providers.ContainsKey(entityId))
                {
                    return providers[entityId];
                }

                OpenIDProviderData op = new OpenIDProviderData(opEntry, options);
                providers.Add(entityId, op);
                return op;
            }
        }
    }
}

namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// Root interface for the options objects, handling all configuration of
    /// AuthServices.
    /// </summary>
    public interface IOptions
    {
        /// <summary>
        /// Options for the relying party's behaviour; i.e. everything except
        /// the op list.
        /// </summary>
        IRPOptions RPOptions { get; }

        /// <summary>
        /// Information about known OPs.
        /// </summary>
        OpenIDProviderDictionary OpenIDProviders { get; }
    }
}

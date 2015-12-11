namespace OpenIDClient.HttpModule.Configuration
{
    /// <summary>
    /// Root interface for the options objects, handling all configuration of
    /// AuthServices.
    /// </summary>
    public interface IRPOptions
    {
        /// <summary>
        /// Application root relative path for AuthServices endpoints. The
        /// default should be "/AuthServices".
        /// </summary>
        string ModulePath { get; }
    }
}

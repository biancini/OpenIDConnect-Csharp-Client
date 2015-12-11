﻿namespace OpenIDClient.HttpModule.WebSso
{
    using System.Web;
    using System.Web.SessionState;
    using OpenIDClient.HttpModule.Configuration;

    /// <summary>
    /// A command - corresponds to an action in Mvc.
    /// </summary>
    public interface ICommand
    {
        /// <summary>
        /// Run the command and return a result.
        /// </summary>
        /// <param name="request">The http request that the input
        /// data can be read from.</param>
        /// <param name="options">The options to use when performing the command.</param>
        /// <returns>The results of the command, as a DTO.</returns>
        CommandResult Run(HttpRequestData request, IOptions options, HttpSessionState session);
    }
}

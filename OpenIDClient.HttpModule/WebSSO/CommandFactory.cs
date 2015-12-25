using System;
using System.Collections.Generic;

namespace OpenIDClient.HttpModule.WebSso
{
    /// <summary>
    /// Factory to create the command objects thand handles the incoming http requests.
    /// </summary>
    public static class CommandFactory
    {
        private static readonly ICommand notFoundCommand = new NotFoundCommand();

        /// <summary>
        /// The name of the Sign In Command.
        /// </summary>
        public const string AuthenticateCommandName = "Authenticate";

        /// <summary>
        /// The name of the Sign In Command.
        /// </summary>
        public const string CodeCallbackCommandName = "CodeCallback";

        /// <summary>
        /// The name of the JWKS Command.
        /// </summary>
        public const string JwksCallbackCommandName = "JwksCallback";

        private static readonly IDictionary<string, ICommand> commands =
            new Dictionary<string, ICommand>(StringComparer.OrdinalIgnoreCase) 
            { 
                { AuthenticateCommandName, new AuthenticateCommand() },
                { CodeCallbackCommandName, new CodeCallbackCommand() },
                { JwksCallbackCommandName, new JwksCallbackCommand() },
            };

        /// <summary>
        /// Gets a command for a command name.
        /// </summary>
        /// <param name="commandName">Name of a command. Probably a path. A
        /// leading slash in the command name is ignored.</param>
        /// <returns>A command implementation or notFoundCommand if invalid.</returns>
        public static ICommand GetCommand(string commandName)
        {
            ICommand command;

            if(commandName ==  null)
            {
                throw new ArgumentNullException(nameof(commandName));
            }

            if(commandName.StartsWith("/", StringComparison.OrdinalIgnoreCase))
            {
                commandName = commandName.Substring(1);
            }

            if (commands.TryGetValue(commandName, out command))
            {
                return command;
            }

            return notFoundCommand;
        }
    }
}

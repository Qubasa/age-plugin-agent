package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// getPluginNameFromBinaryName extracts plugin name from binary path
// Returns the plugin name and true if this is a plugin-named binary
func getPluginNameFromBinaryName(binaryPath string) (string, bool) {
	baseName := filepath.Base(binaryPath)
	prefix := "age-plugin-"

	if strings.HasPrefix(baseName, prefix) {
		pluginName := strings.TrimPrefix(baseName, prefix)
		// "agent" is the name of this binary itself, not a plugin
		if pluginName == "agent" {
			return "", false
		}
		return pluginName, true
	}

	return "", false
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `age-plugin-agent - Age plugin proxy agent

Usage:
  age-plugin-agent intercept <plugin1>[,plugin2,...] [shell]
  age-plugin-agent proxy <plugin-name> --age-plugin=<state-machine>
  age-plugin-agent server --plugin <abs-path> [--plugin <abs-path>...] [socket-path]
  age-plugin-agent --help

Commands:
  intercept   Create a shell with specified plugins intercepted
  proxy       Connect to server and proxy stdin/stdout for a plugin
  server      Start the agent server listening on a Unix socket. It runs only
              the plugins given with --plugin, never anything from $PATH.

Environment Variables:
  AGE_PLUGIN_AGENT_SOCKET   Path to Unix domain socket (default: ~/.age-plugin-agent.sock)

Examples:
  # Start the server, allowing only the yubikey plugin
  age-plugin-agent server --plugin "$(command -v age-plugin-yubikey)"

  # Intercept yubikey plugin
  age-plugin-agent intercept yubikey

  # Manually proxy to a plugin, as age would invoke it
  age-plugin-agent proxy yubikey --age-plugin=identity-v1

When invoked via symlink as 'age-plugin-<name>', automatically runs in proxy mode.
`)
}

func main() {
	// Check binary name for automatic proxy mode detection
	if pluginName, isPluginBinary := getPluginNameFromBinaryName(os.Args[0]); isPluginBinary {
		// Automatically run in proxy mode for this plugin
		if err := runProxy(pluginName, os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Parse subcommands normally
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "intercept":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: intercept requires plugin names\n\n")
			printUsage()
			os.Exit(1)
		}
		pluginsArg := os.Args[2]
		plugins := strings.Split(pluginsArg, ",")

		shell := ""
		if len(os.Args) >= 4 {
			shell = os.Args[3]
		}

		if err := runIntercept(plugins, shell); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "proxy":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Error: proxy requires plugin name\n\n")
			printUsage()
			os.Exit(1)
		}
		pluginName := os.Args[2]

		if err := runProxy(pluginName, os.Args[3:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "--help", "-h", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

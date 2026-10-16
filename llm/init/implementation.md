# Implementation Plan

## Overview

This implementation creates an age plugin agent in Go that intercepts age plugin calls and forwards them to a remote server via Unix domain sockets.

## Data Structures

### Protocol Messages

**File: `protocol.go`**

```go
const (
    MaxPluginNameLength = 64
    PluginNamePattern   = `^[a-zA-Z0-9-]+$`
    maxHandshakeLine    = 128
)

var stateMachines = map[string]bool{"identity-v1": true, "recipient-v1": true}
```

**Purpose**: Define constants for the handshake protocol, and `parseStateMachine(args)`, which reads the `--age-plugin=<state-machine>` argument age passes to a plugin.

## Functions by Module

### File: `main.go`

#### `main()` [req.wtb211] [req.csnye0]

**Description**: Entry point for the age-plugin-agent binary. Implements binary name detection logic to determine the execution mode:
1. Extract the binary name from `os.Args[0]`
2. Parse the base name (after any directory path)
3. If the name starts with `age-plugin-`, extract the plugin name suffix and automatically execute in proxy mode for that plugin [req.tjn27i]
4. Otherwise, parse and dispatch to the appropriate subcommand handler based on CLI arguments [req.bpo0ci]

#### `getPluginNameFromBinaryName(binaryPath string) (string, bool)` [req.csnye0] [req.tjn27i]

**Description**: Helper function to extract plugin name from binary path. Returns the plugin name and a boolean indicating whether this is a plugin-named binary:
1. Extract base name using `filepath.Base()`
2. Check if it starts with `age-plugin-` prefix
3. If yes, return the suffix as plugin name and true
4. Otherwise, return empty string and false

### File: `cmd/intercept.go` or `intercept.go`

#### `runIntercept(plugins []string, shell string)` [req.nc6prq] [req.02pjoj]

**Description**: Implementation of the `intercept` subcommand. Creates a temporary directory with symlinks and spawns a shell:
1. Parse the comma-separated list of plugin names
2. Create a temporary directory (use `os.MkdirTemp()`)
3. Get the current executable path using `os.Executable()`
4. For each plugin name, create a symlink `age-plugin-<name>` pointing to the current executable
5. Prepend the temporary directory to `$PATH` environment variable
6. Determine which shell to use (parameter if provided, otherwise `$SHELL`, fallback to `/bin/sh`)
7. Spawn the shell with the modified environment using `exec.Command()`
8. Wait for the shell to exit
9. Clean up the temporary directory on exit (using `defer`)

### File: `cmd/proxy.go` or `proxy.go`

#### `runProxy(pluginName string, args []string)` [req.nc6prq] [req.erkwws]

**Description**: Implementation of the `proxy` subcommand. Connects to the server and proxies stdin/stdout:
1. Parse the state machine from `args` (call `parseStateMachine()`)
2. Connect to the Unix domain socket from `getSocketPath()`
3. Perform the client-side handshake (call `performClientHandshake()`)
4. If handshake fails, write error to stderr and exit with non-zero status
5. If handshake succeeds, proxy with `pipe()`:
   - A goroutine copies stdin to the socket, then half-closes the socket for writing
   - The main goroutine copies from the handshake reader to stdout
   - Return as soon as the server closes the connection. Never wait for stdin to end: age keeps it open until it has read the plugin's answer, so waiting deadlocks when the plugin fails

#### `performClientHandshake(conn net.Conn, pluginName, stateMachine string) (*bufio.Reader, error)` [req.erkwws]

**Description**: Handles the client side of the handshake protocol:
1. Validate plugin name and state machine
2. Write `<plugin-name> <state-machine>\n`
3. Read the response line, with a 10 second timeout
4. On `OK`, return the reader, which may already hold plugin output
5. On `ERROR <msg>`, return the message as an error; anything else is an unexpected response

### File: `cmd/server.go` or `server.go`

#### `runServer(args []string)` [req.nc6prq] [req.lv5ejb] [req.nytk77]

**Description**: Implementation of the `server` subcommand:
1. Parse repeatable `--plugin <abs-path>` flags and an optional socket path
2. Build the plugin allowlist (call `loadPlugins()`)
3. Bind the socket (call `listen()`)
4. Set up signal handling (SIGINT, SIGTERM) that closes the listener
5. Accept connections (call `serve()`), one `handleConnection()` goroutine each

**Note**: Server emits operational logs to stdout and stderr. Plugin stderr is passed through, so a plugin's own log ends up in the server's.

#### `loadPlugins(paths []string) (map[string]string, error)` [req.lv5ejb]

**Description**: Maps plugin names to the only executables the server may run. Each path must be absolute, named `age-plugin-<name>` with a valid name other than `agent`, a regular executable file, and not repeat a name. `$PATH` is never searched: the client picks the name, so anything able to write to a `$PATH` directory could otherwise choose what the server executes.

#### `listen(socketPath string) (*net.UnixListener, error)` [req.nytk77]

**Description**: Replaces a stale socket but refuses to remove anything that is not a socket. Binds under umask 077, so the socket is never accessible to group or others.

#### `performServerHandshake(conn net.Conn, plugins map[string]string)` [req.lv5ejb]

**Description**: Handles the server side of the handshake protocol:
1. Set a 10 second read timeout
2. Read one line of at most 128 bytes
3. Split it into plugin name and state machine, validate both, and look the name up in the allowlist
4. On failure, send `ERROR <message>\n` without echoing unvalidated input
5. On success, send `OK\n` and return the plugin path, state machine, and the reader holding any further client bytes

#### `proxyToPlugin(conn *net.UnixConn, fromConn io.Reader, pluginPath, stateMachine string)` [req.lv5ejb]

**Description**: Spawns the plugin and proxies data bidirectionally:
1. Run `<pluginPath> --age-plugin=<stateMachine>` with stdin/stdout pipes
2. A goroutine copies from the client to the plugin's stdin
3. Copy the plugin's stdout to the socket until EOF, and only then call `cmd.Wait()`, which closes the pipe and would otherwise drop the plugin's last messages
4. Close the connection

### File: `util.go` or `validation.go`

#### `validatePluginName(name string) error`

**Description**: Validates plugin name format according to protocol requirements:
1. Check if name is empty (return error if so)
2. Check if length exceeds 64 characters (return error if so)
3. Compile and match against regex `^[a-zA-Z0-9-]+$`
4. Return nil if valid, descriptive error otherwise

Used by both client and server for consistent validation.

### File: `socket.go` or `config.go`

#### `getSocketPath() string` [req.nytk77]

**Description**: Determines the Unix domain socket path to use:
1. Check for environment variable (e.g., `AGE_PLUGIN_AGENT_SOCKET`)
2. If not set, use a default path (e.g., `/tmp/age-plugin-agent.sock` or `~/.age-plugin-agent.sock`)
3. Return the resolved path

This function is used by both client and server to ensure they use the same socket location.

## Implementation Notes

### Functional Programming Approach

- All functions are designed to be as pure as possible
- Side effects (I/O operations, process spawning) are isolated in dedicated functions
- Helper functions like `validatePluginName()` and `getPluginNameFromBinaryName()` are pure functions
- State mutation is limited to necessary I/O operations

### Early Returns

- Validation functions return early on first error
- Handshake functions check and return at each validation step
- Error handling uses early returns to reduce nesting

### Error Handling

- All errors are propagated with descriptive messages
- Server sends structured error responses to clients
- Client displays errors to stderr before exiting
- Network timeouts prevent indefinite blocking

### Logging

- Server emits operational logs to stdout for monitoring and debugging
- Log messages include: server startup, connection events, plugin execution, and errors
- Client proxy mode operates silently (no logs) to avoid interfering with age protocol on stdout

### Security Considerations

- The server only runs plugins from its `--plugin` allowlist, by absolute path
- Plugin name and state machine validation prevents path traversal and argument injection
- The handshake line is bounded and invalid input is not echoed
- The socket is created owner-only
- No global variables; configuration passed through function parameters or struct fields

### Concurrency

- Server handles each connection in a separate goroutine
- Bidirectional proxying uses goroutines for concurrent reads/writes
- Proper cleanup with defer statements
- No shared mutable state between goroutines

## Requirement Coverage

- [req.wtb211] - Go executable created
- [req.csnye0] - Binary name detection implemented in `main()`
- [req.tjn27i] - Automatic proxy mode when called as `age-plugin-*`
- [req.bpo0ci] - Normal subcommand parsing when called directly
- [req.nc6prq] - Subcommands implemented: `intercept`, `proxy`, `server`
- [req.02pjoj] - Intercept creates symlinks for specified plugins
- [req.erkwws] - Proxy performs handshake and proxies stdin/stdout
- [req.lv5ejb] - Server listens on socket, performs handshake, and proxies to plugin
- [req.nytk77] - Unix domain socket used for communication

# Objective

Implement an age plugin that allows users to forward encryption and decryption operations to a remote server.

# Architecture

The client implements the `age plugin` protocol and forwards requests to the server. The server performs the actual encryption and decryption operations by calling the appropriate plugin (or the `age` binary directly).

## Interception

Age encryption needs a **recipient**. 

Age decryption needs an **identity**.

Either of those can be either a local file or an age plugin. If it's an age plugin, age will automatically call that plugin with the corresponding binary from the $PATH.

`age-plugin-agent` will intercept the call by **replacing** the `age-plugin-[name]` in the current environment. This is done by executing `age-plugin-agent intercept plugin1,plugin2 [shell (optional)]`, which will spin up a shell that has `age-plugin-plugin1` and `age-plugin-plugin2` in the $PATH, both pointing to `age-plugin-agent`. 

Those would be equivalent:

```bash
age-plugin-agent intercept yubikey
```

```bash
alias age-plugin-yubikey='age-plugin-agent'
```

# Implementation

* Go executable called `age-plugin-agent`. [req.wtb211]
* **Binary Name Detection**: The binary should check its own name (via `os.Args[0]`) on startup: [req.csnye0]
	* If the binary name starts with `age-plugin-` (e.g., called via symlink as `age-plugin-yubikey`), extract the plugin name and automatically run in `proxy` mode for that plugin. [req.tjn27i]
	* Otherwise, parse subcommands normally. [req.bpo0ci]
* Subcommands: [req.nc6prq]
	* `intercept`: Spins up a shell with the specified plugins in the $PATH. Creates symlinks to `age-plugin-agent` named `age-plugin-<name>` for each specified plugin, allowing automatic detection via binary name. [req.02pjoj]
	* `proxy <plugin-name> --age-plugin=<state-machine>`: Connects to the server socket, performs the handshake protocol (sends plugin name and the state machine age requested, receives OK/ERROR), then forwards STDIN to the socket and forwards responses from the socket back to STDOUT. It exits once the server closes the connection, without waiting for STDIN to end, because age keeps a plugin's STDIN open until it has the plugin's answer. [req.erkwws]
	* `server --plugin <abs-path> [--plugin <abs-path>...] [socket-path]`: Spins up the server that listens on a Unix domain socket for plugin requests. Only the plugins given with `--plugin` can run, each an absolute path to an executable named `age-plugin-<name>`; `$PATH` is never searched, since the client chooses the name. For each connection, it performs the handshake protocol, spawns the chosen plugin as `<path> --age-plugin=<state-machine>`, and transparently proxies data between the socket and the plugin's stdin/stdout. Once the plugin binary exits and its output has been forwarded, the server closes the connection. The socket is created with mode 0600. [req.lv5ejb]
* Socket: the socket is simply a file. The server listens on that socket for incoming plugin requests. The client connects to that socket and sends the plugin request. The server then forwards the request to the appropriate plugin and sends the response back to the client. This is meant to be used by forwarding the file via SSH. [req.nytk77]

## Handshake Protocol

Before proxying data to the plugin, the client and server perform a handshake to establish which plugin to execute and handle any initialization errors.

### Protocol Flow

1. **Client connects** to the Unix domain socket
2. **Client sends plugin name and state machine**: `<plugin-name> <state-machine>\n`
   - Example: `yubikey identity-v1\n`
   - Plugin name must be alphanumeric with optional hyphens (validated by regex: `^[a-zA-Z0-9-]+$`), max 64 characters
   - State machine is `identity-v1` or `recipient-v1`, as age passes it in `--age-plugin=<state-machine>`
   - The server reads at most 128 bytes for this line
3. **Server validates and responds**:
   - **Success case**: Server sends `OK\n` and begins transparent proxying
   - **Error case**: Server sends `ERROR <message>\n` and closes the connection
4. **After successful handshake**: Bidirectional transparent proxying begins
   - Client proxies: stdin → socket, socket → stdout
   - Server proxies: socket → plugin stdin, plugin stdout → socket
5. **Connection termination**: When plugin exits, server closes the socket connection

### Server-Side Plugin Selection

When the server receives a handshake line:

1. Validate the plugin name format (alphanumeric + hyphens only, max 64 chars)
2. Validate the state machine (`identity-v1` or `recipient-v1`)
3. Look the name up among the plugins passed with `--plugin`
4. If any check fails, send an error response and close the connection
5. Otherwise send `OK\n`

### Error Messages

Client input is never echoed back unless it passed validation:
- `ERROR invalid handshake\n` - Line missing, too long, or without a state machine
- `ERROR invalid plugin name\n` - Plugin name contains invalid characters
- `ERROR unsupported state machine\n` - State machine is not `identity-v1` or `recipient-v1`
- `ERROR plugin not allowed: <name>\n` - Plugin was not passed to the server with `--plugin`

### Example Exchange

**Successful handshake:**
```
Client → Server: yubikey identity-v1\n
Server → Client: OK\n
[transparent proxying begins]
```

**Failed handshake (plugin not allowed):**
```
Client → Server: nonexistent identity-v1\n
Server → Client: ERROR plugin not allowed: nonexistent\n
[connection closes]
```

**Failed handshake (invalid name):**
```
Client → Server: ../../../etc/passwd identity-v1\n
Server → Client: ERROR invalid plugin name\n
[connection closes]
```

# age-plugin-hostkey

A second binary, `age-plugin-hostkey`, meant to be the plugin the server runs. It lets a client decrypt files encrypted to native age keys (`AGE-SECRET-KEY-1…`, `AGE-SECRET-KEY-PQ-1…`) that only exist on the server's host.

* The client's identity file holds a placeholder with no secret, printed by `age-plugin-hostkey --print-identity`: one `# recipient: age1…` comment per host key, then `AGE-PLUGIN-HOSTKEY-1…`. Tools such as clan read the public keys from the comments.
* On `identity-v1`, it unwraps with every key in `AGE_PLUGIN_HOSTKEY_FILE` (default `$XDG_CONFIG_HOME/sops/age/keys.txt`) and returns the file key of the first one that matches.
* It asks nobody. Whoever can reach the server's socket can decrypt every file encrypted to those keys, so access is decided by who may connect to the socket.
* Each released file key is logged to stderr with time and recipient. Under the server, that is the server's log.

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// loadPlugins maps plugin names to the executables the server may run. Only
// these run: the client picks a name, so searching PATH would let anything
// that can write to a PATH directory choose what the server executes.
func loadPlugins(paths []string) (map[string]string, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one --plugin is required")
	}
	plugins := make(map[string]string, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("plugin path must be absolute: %s", path)
		}
		name, ok := getPluginNameFromBinaryName(path)
		if !ok {
			return nil, fmt.Errorf("plugin binary must be named age-plugin-<name>: %s", path)
		}
		if err := validatePluginName(name); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if _, dup := plugins[name]; dup {
			return nil, fmt.Errorf("plugin %q given twice", name)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("plugin not found: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return nil, fmt.Errorf("plugin not executable: %s", path)
		}
		plugins[name] = path
	}
	return plugins, nil
}

// performServerHandshake reads "<plugin> <state-machine>" and answers OK or
// ERROR. It returns the reader the client's further bytes must come from.
func performServerHandshake(
	conn net.Conn, plugins map[string]string,
) (string, string, *bufio.Reader, error) {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", "", nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	reject := func(msg string) (string, string, *bufio.Reader, error) {
		_, _ = fmt.Fprintf(conn, "ERROR %s\n", msg)
		return "", "", nil, errors.New(msg)
	}

	reader := bufio.NewReaderSize(conn, maxHandshakeLine)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return reject("invalid handshake")
	}
	name, stateMachine, ok := strings.Cut(strings.TrimSuffix(string(line), "\n"), " ")
	if !ok {
		return reject("invalid handshake")
	}
	if validatePluginName(name) != nil {
		return reject("invalid plugin name")
	}
	if validateStateMachine(stateMachine) != nil {
		return reject("unsupported state machine")
	}
	pluginPath, allowed := plugins[name]
	if !allowed {
		return reject("plugin not allowed: " + name)
	}

	if _, err := conn.Write([]byte("OK\n")); err != nil {
		return "", "", nil, fmt.Errorf("failed to send OK response: %w", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", "", nil, fmt.Errorf("failed to clear read deadline: %w", err)
	}
	return pluginPath, stateMachine, reader, nil
}

func handleConnection(conn *net.UnixConn, plugins map[string]string) {
	defer conn.Close()

	pluginPath, stateMachine, reader, err := performServerHandshake(conn, plugins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Handshake failed: %v\n", err)
		return
	}
	fmt.Printf("Running %s --age-plugin=%s\n", pluginPath, stateMachine)

	if err := proxyToPlugin(conn, reader, pluginPath, stateMachine); err != nil {
		fmt.Fprintf(os.Stderr, "Plugin proxy error: %v\n", err)
	}
}

// listen binds the socket with no group or other permissions from the start.
// An existing socket from a previous run is replaced, anything else is not.
func listen(socketPath string) (*net.UnixListener, error) {
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("failed to remove existing socket: %w", err)
		}
	}
	oldMask := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	syscall.Umask(oldMask)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket listener: %w", err)
	}
	return listener, nil
}

// serve accepts connections until the listener is closed.
func serve(listener *net.UnixListener, plugins map[string]string) error {
	for {
		conn, err := listener.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}
		go handleConnection(conn, plugins)
	}
}

// runServer implements the server subcommand.
func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var pluginPaths stringList
	fs.Var(&pluginPaths, "plugin", "absolute path of an age-plugin-<name> the server may run (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	socketPath := getSocketPath()
	switch fs.NArg() {
	case 0:
	case 1:
		socketPath = fs.Arg(0)
	default:
		return fmt.Errorf("unexpected arguments: %q", fs.Args()[1:])
	}

	plugins, err := loadPlugins(pluginPaths)
	if err != nil {
		return err
	}
	listener, err := listen(socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received shutdown signal, stopping server...")
		listener.Close()
	}()

	fmt.Printf("Server started, listening on: %s\n", socketPath)
	return serve(listener, plugins)
}

// proxyToPlugin runs the plugin and proxies between it and the client until
// the plugin exits. The plugin's stdout is drained before Wait, because Wait
// closes the pipe and would otherwise drop the plugin's last messages.
func proxyToPlugin(conn *net.UnixConn, fromConn io.Reader, pluginPath, stateMachine string) error {
	cmd := exec.Command(pluginPath, stateMachineFlag+"="+stateMachine)
	pluginStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	pluginStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	go func() {
		_, _ = io.Copy(pluginStdin, fromConn)
		_ = pluginStdin.Close()
	}()

	_, copyErr := io.Copy(conn, pluginStdout)
	waitErr := cmd.Wait()
	conn.Close()

	if waitErr != nil {
		return fmt.Errorf("plugin process error: %w", waitErr)
	}
	if copyErr != nil {
		return fmt.Errorf("plugin to socket error: %w", copyErr)
	}
	return nil
}

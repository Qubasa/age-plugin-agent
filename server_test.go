package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePlugin(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, "age-plugin-"+name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func startServer(t *testing.T, pluginPaths ...string) string {
	t.Helper()
	plugins, err := loadPlugins(pluginPaths)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := shortSocketPath(t)
	listener, err := listen(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() { _ = serve(listener, plugins) }()
	return socketPath
}

func dial(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// runClient proxies like age-plugin-agent's proxy mode does, with a stdin
// that never reaches EOF, as age's never does while it waits for the plugin.
func runClient(t *testing.T, socketPath, plugin string) []byte {
	t.Helper()
	conn := dial(t, socketPath)
	reader, err := performClientHandshake(conn, plugin, "identity-v1")
	if err != nil {
		t.Fatal(err)
	}
	stdin, stdinWriter := io.Pipe()
	t.Cleanup(func() { stdinWriter.Close() })

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- pipe(conn, reader, stdin, &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not return after the plugin exited")
	}
	return out.Bytes()
}

func TestProxyRunsPluginWithStateMachine(t *testing.T) {
	dir := t.TempDir()
	socketPath := startServer(t, writePlugin(t, dir, "echo", `echo "$@"`))

	out := runClient(t, socketPath, "echo")

	if got, want := string(out), "--age-plugin=identity-v1\n"; got != want {
		t.Errorf("plugin saw arguments %q, want %q", got, want)
	}
}

func TestProxyDeliversAllPluginOutput(t *testing.T) {
	const size = 1 << 20
	dir := t.TempDir()
	socketPath := startServer(t, writePlugin(t, dir, "big", "head -c 1048576 /dev/zero"))

	out := runClient(t, socketPath, "big")

	if len(out) != size {
		t.Errorf("received %d bytes of plugin output, want %d", len(out), size)
	}
}

func TestServerRefusesPluginsNotOnItsList(t *testing.T) {
	dir := t.TempDir()
	socketPath := startServer(t, writePlugin(t, dir, "allowed", "exit 0"))
	writePlugin(t, dir, "other", "exit 0")

	_, err := performClientHandshake(dial(t, socketPath), "other", "identity-v1")

	if err == nil || !strings.Contains(err.Error(), "plugin not allowed: other") {
		t.Errorf("handshake error = %v, want plugin not allowed", err)
	}
}

func TestServerRejectsMalformedHandshakes(t *testing.T) {
	dir := t.TempDir()
	socketPath := startServer(t, writePlugin(t, dir, "allowed", "exit 0"))
	tests := map[string]string{
		"allowed keygen-v1\n":                   "ERROR unsupported state machine\n",
		"allowed\n":                             "ERROR invalid handshake\n",
		"../x identity-v1\n":                    "ERROR invalid plugin name\n",
		strings.Repeat("a", maxHandshakeLine*2): "ERROR invalid handshake\n",
		"allowed identity-v1 --evil=1\n":        "ERROR unsupported state machine\n",
		"allowed --age-plugin=identity-v1\n":    "ERROR unsupported state machine\n",
	}
	for request, want := range tests {
		conn := dial(t, socketPath)
		if _, err := conn.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		got, _ := bufio.NewReader(conn).ReadString('\n')
		if got != want {
			t.Errorf("request %.40q: got %q, want %q", request, got, want)
		}
	}
}

func TestLoadPlugins(t *testing.T) {
	dir := t.TempDir()
	good := writePlugin(t, dir, "good", "exit 0")
	agent := writePlugin(t, dir, "agent", "exit 0")
	notExec := filepath.Join(dir, "age-plugin-noexec")
	if err := os.WriteFile(notExec, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wrongName := filepath.Join(dir, "rage")
	if err := os.WriteFile(wrongName, nil, 0o755); err != nil {
		t.Fatal(err)
	}

	tests := map[string][]string{
		"no plugins":       nil,
		"relative path":    {"age-plugin-good"},
		"not age-plugin-*": {wrongName},
		"the agent itself": {agent},
		"not executable":   {notExec},
		"missing":          {filepath.Join(dir, "age-plugin-missing")},
		"directory":        {filepath.Join(dir, "age-plugin-dir")},
		"duplicate":        {good, good},
	}
	if err := os.Mkdir(filepath.Join(dir, "age-plugin-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, paths := range tests {
		if _, err := loadPlugins(paths); err == nil {
			t.Errorf("%s: loadPlugins(%q) succeeded, want error", name, paths)
		}
	}

	plugins, err := loadPlugins([]string{good})
	if err != nil {
		t.Fatal(err)
	}
	if plugins["good"] != good || len(plugins) != 1 {
		t.Errorf("loadPlugins = %v, want only good -> %s", plugins, good)
	}
}

func TestListenRefusesToReplaceNonSocket(t *testing.T) {
	path := shortSocketPath(t)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(path); err == nil {
		t.Fatal("listen replaced a regular file")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Error("regular file was modified")
	}
}

func TestListenCreatesOwnerOnlySocket(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("socket mode %o is accessible to group or others", perm)
	}
}

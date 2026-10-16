package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// performClientHandshake sends "<plugin> <state-machine>" and waits for OK.
// It returns the reader the plugin's output must be read from, since it may
// already hold bytes that arrived after the OK line.
func performClientHandshake(conn net.Conn, pluginName, stateMachine string) (*bufio.Reader, error) {
	if err := validatePluginName(pluginName); err != nil {
		return nil, fmt.Errorf("invalid plugin name: %w", err)
	}
	if err := validateStateMachine(stateMachine); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s %s\n", pluginName, stateMachine); err != nil {
		return nil, fmt.Errorf("failed to send handshake: %w", err)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}
	response = strings.TrimSpace(response)

	if response == "OK" {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("failed to clear read deadline: %w", err)
		}
		return reader, nil
	}
	if errorMsg, ok := strings.CutPrefix(response, "ERROR "); ok {
		return nil, fmt.Errorf("server error: %s", errorMsg)
	}
	return nil, fmt.Errorf("unexpected handshake response: %s", response)
}

// pipe copies in to the socket and the socket to out. It returns once the
// server closes the connection, which happens when the plugin exits. It does
// not wait for in to reach EOF: age keeps the plugin's stdin open until it
// has read the plugin's final answer, so waiting would deadlock when the
// plugin fails.
func pipe(conn *net.UnixConn, fromConn io.Reader, in io.Reader, out io.Writer) error {
	go func() {
		if _, err := io.Copy(conn, in); err == nil {
			_ = conn.CloseWrite()
		}
	}()
	_, err := io.Copy(out, fromConn)
	return err
}

// runProxy connects to the server and proxies stdin/stdout for one plugin
// invocation. args are the arguments age passed to the plugin.
func runProxy(pluginName string, args []string) error {
	stateMachine, err := parseStateMachine(args)
	if err != nil {
		return err
	}

	socketPath := getSocketPath()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("failed to connect to server at %s: %w", socketPath, err)
	}
	defer conn.Close()

	reader, err := performClientHandshake(conn, pluginName, stateMachine)
	if err != nil {
		return err
	}
	return pipe(conn, reader, os.Stdin, os.Stdout)
}

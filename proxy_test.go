package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocketPath keeps the path under the 108-byte AF_UNIX limit.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "apa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func TestPerformClientHandshake(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		errContains    string
	}{
		{name: "ok", serverResponse: "OK\n"},
		{
			name:           "server error",
			serverResponse: "ERROR plugin not allowed: yubikey\n",
			errContains:    "plugin not allowed",
		},
		{
			name:           "garbage response",
			serverResponse: "HELLO\n",
			errContains:    "unexpected handshake response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("unix", shortSocketPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			received := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				received <- line
				_, _ = conn.Write([]byte(tt.serverResponse))
			}()

			conn, err := net.Dial("unix", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			_, err = performClientHandshake(conn, "yubikey", "identity-v1")

			select {
			case line := <-received:
				if line != "yubikey identity-v1\n" {
					t.Errorf("server received %q, want %q", line, "yubikey identity-v1\n")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server never received the handshake")
			}
			switch {
			case tt.errContains == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.errContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errContains)):
				t.Errorf("error = %v, want it to contain %q", err, tt.errContains)
			}
		})
	}
}

func TestPerformClientHandshakeRejectsBadInputBeforeSending(t *testing.T) {
	if _, err := performClientHandshake(nil, "../../../etc/passwd", "identity-v1"); err == nil {
		t.Error("expected invalid plugin name error")
	}
	if _, err := performClientHandshake(nil, "yubikey", "keygen"); err == nil {
		t.Error("expected unsupported state machine error")
	}
}

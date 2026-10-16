package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

func writeKeyFile(t *testing.T, dir string) (string, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keys.txt")
	content := "# created: test\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id
}

func encrypt(t *testing.T, recipient age.Recipient, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newIdentity(t *testing.T, keyFile string, log io.Writer) *hostIdentity {
	t.Helper()
	keys, err := loadKeys(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return &hostIdentity{keys: keys, log: log}
}

func decrypt(ciphertext []byte, id age.Identity) (string, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return "", err
	}
	out, err := io.ReadAll(r)
	return string(out), err
}

func TestDecryptsWithTheHostKeyAndLogsTheRelease(t *testing.T) {
	keyFile, id := writeKeyFile(t, t.TempDir())
	var log bytes.Buffer

	got, err := decrypt(encrypt(t, id.Recipient(), "secret"), newIdentity(t, keyFile, &log))

	if err != nil || got != "secret" {
		t.Fatalf("decrypted %q, %v, want %q", got, err, "secret")
	}
	if !strings.Contains(log.String(), id.Recipient().String()+": released") {
		t.Errorf("log %q does not record the release", log.String())
	}
}

func TestFilesForOtherKeysReleaseNothing(t *testing.T) {
	keyFile, _ := writeKeyFile(t, t.TempDir())
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer

	_, err = decrypt(encrypt(t, other.Recipient(), "not yours"), newIdentity(t, keyFile, &log))

	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Errorf("error = %v, want NoIdentityMatchError", err)
	}
	if log.Len() != 0 {
		t.Errorf("logged %q for a file not encrypted to the host key", log.String())
	}
}

func TestPrintIdentityHoldsNoSecret(t *testing.T) {
	dir := t.TempDir()
	keyFile, id := writeKeyFile(t, dir)
	keys, err := loadKeys(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printIdentity(&out, keys); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != "# recipient: "+id.Recipient().String() {
		t.Fatalf("printed %q, want a recipient comment then one identity", out.String())
	}
	name, data, err := plugin.ParseIdentity(lines[1])
	if err != nil || name != pluginName || len(data) != 0 {
		t.Errorf("identity line %q: name %q, data %x, err %v", lines[1], name, data, err)
	}
	if strings.Contains(out.String(), "AGE-SECRET-KEY") {
		t.Error("placeholder identity contains a private key")
	}
}

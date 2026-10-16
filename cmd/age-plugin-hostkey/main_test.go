package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// fakeZenity stands in for the GUI dialog: it records each call and answers
// with exitCode, as zenity does (0 allow, 1 deny).
func fakeZenity(t *testing.T, dir string, exitCode int) (string, func() int) {
	t.Helper()
	calls := filepath.Join(dir, "calls")
	path := filepath.Join(dir, "zenity")
	script := "#!/bin/sh\necho x >> " + calls + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		data, _ := os.ReadFile(calls)
		return strings.Count(string(data), "x")
	}
	return path, count
}

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

func newIdentity(t *testing.T, cfg config) *hostIdentity {
	t.Helper()
	keys, err := loadKeys(cfg.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return &hostIdentity{cfg: cfg, keys: keys, log: io.Discard}
}

func decrypt(ciphertext []byte, id age.Identity) (string, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return "", err
	}
	out, err := io.ReadAll(r)
	return string(out), err
}

func setup(t *testing.T, zenityExit int, ttl time.Duration) (config, *age.X25519Identity, func() int) {
	t.Helper()
	dir := t.TempDir()
	keyFile, id := writeKeyFile(t, dir)
	zenity, calls := fakeZenity(t, dir, zenityExit)
	cfg := config{keyFile: keyFile, ttl: ttl, stateDir: filepath.Join(dir, "state"), zenity: zenity}
	return cfg, id, calls
}

func TestApprovedDecryptionIsRememberedForTTL(t *testing.T) {
	cfg, id, calls := setup(t, 0, time.Hour)
	ciphertext := encrypt(t, id.Recipient(), "secret")

	for range 3 {
		got, err := decrypt(ciphertext, newIdentity(t, cfg))
		if err != nil {
			t.Fatal(err)
		}
		if got != "secret" {
			t.Fatalf("decrypted %q, want %q", got, "secret")
		}
	}
	if calls() != 1 {
		t.Errorf("prompted %d times within the TTL, want 1", calls())
	}
}

func TestExpiredApprovalPromptsAgain(t *testing.T) {
	cfg, id, calls := setup(t, 0, time.Hour)
	ciphertext := encrypt(t, id.Recipient(), "secret")
	if _, err := decrypt(ciphertext, newIdentity(t, cfg)); err != nil {
		t.Fatal(err)
	}
	if err := writeDeadline(filepath.Join(cfg.stateDir, "approved-until"),
		time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := decrypt(ciphertext, newIdentity(t, cfg)); err != nil {
		t.Fatal(err)
	}
	if calls() != 2 {
		t.Errorf("prompted %d times, want 2", calls())
	}
}

func TestZeroTTLPromptsEveryTime(t *testing.T) {
	cfg, id, calls := setup(t, 0, 0)
	ciphertext := encrypt(t, id.Recipient(), "secret")

	for range 2 {
		if _, err := decrypt(ciphertext, newIdentity(t, cfg)); err != nil {
			t.Fatal(err)
		}
	}
	if calls() != 2 {
		t.Errorf("prompted %d times, want 2", calls())
	}
}

func TestDeniedDecryptionReleasesNothing(t *testing.T) {
	cfg, id, _ := setup(t, 1, time.Hour)
	ciphertext := encrypt(t, id.Recipient(), "secret")

	got, err := decrypt(ciphertext, newIdentity(t, cfg))

	if !errors.Is(err, errDenied) {
		t.Errorf("error = %v, want %v", err, errDenied)
	}
	if got != "" {
		t.Errorf("decrypted %q despite denial", got)
	}
	if _, err := os.Stat(filepath.Join(cfg.stateDir, "approved-until")); err == nil {
		t.Error("a denial was recorded as an approval")
	}
}

func TestMissingDialogDenies(t *testing.T) {
	cfg, id, _ := setup(t, 0, time.Hour)
	cfg.zenity = filepath.Join(t.TempDir(), "no-such-zenity")
	ciphertext := encrypt(t, id.Recipient(), "secret")

	if _, err := decrypt(ciphertext, newIdentity(t, cfg)); err == nil {
		t.Error("decrypted without a working approval dialog")
	}
}

func TestFilesForOtherKeysNeverPrompt(t *testing.T) {
	cfg, _, calls := setup(t, 0, time.Hour)
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encrypt(t, other.Recipient(), "not yours")

	_, err = decrypt(ciphertext, newIdentity(t, cfg))

	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Errorf("error = %v, want NoIdentityMatchError", err)
	}
	if calls() != 0 {
		t.Errorf("prompted %d times for a file not encrypted to the host key", calls())
	}
}

func TestStateDirectoryWritableByOthersIsRefused(t *testing.T) {
	cfg, id, calls := setup(t, 0, time.Hour)
	if err := os.MkdirAll(cfg.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeDeadline(filepath.Join(cfg.stateDir, "approved-until"),
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := decrypt(encrypt(t, id.Recipient(), "secret"), newIdentity(t, cfg)); err == nil {
		t.Error("decrypted using approval state others could have written")
	}
	if calls() != 0 {
		t.Errorf("prompted %d times, want 0", calls())
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

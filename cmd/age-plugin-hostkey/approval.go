package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	promptTimeoutSeconds = 60
	zenityCancel         = 1
	zenityTimeout        = 5
)

var errDenied = errors.New("decryption denied on the host")

// approve asks on the host before a file key is released. An approval is
// remembered for cfg.ttl in a file only the host user can write. Concurrent
// plugin processes serialize on a lock, so one dialog covers all of them.
func approve(cfg config, recipient string) (string, error) {
	if cfg.ttl == 0 || cfg.stateDir == "" {
		return ask(cfg, recipient)
	}
	if err := ensurePrivateDir(cfg.stateDir); err != nil {
		return "error", err
	}
	lock, err := os.OpenFile(filepath.Join(cfg.stateDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "error", err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "error", fmt.Errorf("lock approval state: %w", err)
	}

	stateFile := filepath.Join(cfg.stateDir, "approved-until")
	if until, ok := readDeadline(stateFile); ok && time.Now().Before(until) {
		return "approved (until " + until.Format(time.RFC3339) + ")", nil
	}
	decision, err := ask(cfg, recipient)
	if err != nil {
		return decision, err
	}
	until := time.Now().Add(cfg.ttl)
	if err := writeDeadline(stateFile, until); err != nil {
		return "error", err
	}
	return decision + " (until " + until.Format(time.RFC3339) + ")", nil
}

func ask(cfg config, recipient string) (string, error) {
	text := fmt.Sprintf("Release an age file key decrypted with your host key?\n\n"+
		"Key: %s\nApproval lasts: %s", recipient, cfg.ttl)
	cmd := exec.Command(cfg.zenity, "--question", "--no-markup",
		"--title=age-plugin-hostkey", "--text="+text,
		"--ok-label=Allow", "--cancel-label=Deny",
		"--timeout="+strconv.Itoa(promptTimeoutSeconds))
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return "approved", nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() == zenityCancel:
		return "denied", errDenied
	case errors.As(err, &exitErr) && exitErr.ExitCode() == zenityTimeout:
		return "timed out", errDenied
	default:
		return "error", fmt.Errorf("approval dialog failed, nothing released: %w", err)
	}
}

// ensurePrivateDir refuses a state directory that is a symlink or that
// anyone but the owner could write, since its contents grant approval.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("approval state %s must be a directory with mode 0700", dir)
	}
	return nil
}

func readDeadline(path string) (time.Time, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

func writeDeadline(path string, until time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(until.Unix(), 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

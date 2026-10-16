package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const pluginName = "hostkey"

func keyFilePath() (string, error) {
	if path := os.Getenv("AGE_PLUGIN_HOSTKEY_FILE"); path != "" {
		return path, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "sops", "age", "keys.txt"), nil
}

type hostKey struct {
	identity  age.Identity
	recipient string
}

func loadKeys(path string) ([]hostKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	keys := make([]hostKey, 0, len(identities))
	for _, identity := range identities {
		switch id := identity.(type) {
		case *age.X25519Identity:
			keys = append(keys, hostKey{identity: id, recipient: id.Recipient().String()})
		case *age.HybridIdentity:
			keys = append(keys, hostKey{identity: id, recipient: id.Recipient().String()})
		default:
			return nil, fmt.Errorf("%s: unsupported identity type %T", path, identity)
		}
	}
	return keys, nil
}

type hostIdentity struct {
	keys []hostKey
	log  io.Writer
}

func (h *hostIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, key := range h.keys {
		fileKey, err := key.identity.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(h.log, "age-plugin-hostkey: %s %s: released\n",
			time.Now().Format(time.RFC3339), key.recipient)
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

// printIdentity writes the placeholder identity file for clients. The
// recipient comments let tools such as clan find the public keys without the
// private ones.
func printIdentity(w io.Writer, keys []hostKey) error {
	for _, key := range keys {
		if _, err := fmt.Fprintf(w, "# recipient: %s\n", key.recipient); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, plugin.EncodeIdentity(pluginName, nil))
	return err
}

func run() int {
	p, err := plugin.New(pluginName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	p.RegisterFlags(nil)
	printID := flag.Bool("print-identity", false,
		"print the placeholder identity file for the keys in the key file")
	flag.Parse()

	keyFile, err := keyFilePath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-plugin-hostkey: %v\n", err)
		return 1
	}

	if *printID {
		keys, err := loadKeys(keyFile)
		if err == nil {
			err = printIdentity(os.Stdout, keys)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "age-plugin-hostkey: %v\n", err)
			return 1
		}
		return 0
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		if len(data) != 0 {
			return nil, errors.New("unexpected identity data")
		}
		keys, err := loadKeys(keyFile)
		if err != nil {
			return nil, err
		}
		return &hostIdentity{keys: keys, log: os.Stderr}, nil
	})
	return p.Main()
}

func main() {
	os.Exit(run())
}

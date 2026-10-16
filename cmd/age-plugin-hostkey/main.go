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

// zenityPath is the default approval dialog. Nix builds set it to a store path.
var zenityPath = "zenity"

type config struct {
	keyFile  string
	ttl      time.Duration
	stateDir string
	zenity   string
}

func loadConfig() (config, error) {
	cfg := config{
		keyFile: os.Getenv("AGE_PLUGIN_HOSTKEY_FILE"),
		ttl:     15 * time.Minute,
		zenity:  zenityPath,
	}
	if cfg.keyFile == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return config{}, err
		}
		cfg.keyFile = filepath.Join(configDir, "sops", "age", "keys.txt")
	}
	if raw := os.Getenv("AGE_PLUGIN_HOSTKEY_TTL"); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil || ttl < 0 {
			return config{}, fmt.Errorf("AGE_PLUGIN_HOSTKEY_TTL: invalid duration %q", raw)
		}
		cfg.ttl = ttl
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		cfg.stateDir = filepath.Join(runtimeDir, "age-plugin-hostkey")
	}
	if zenity := os.Getenv("AGE_PLUGIN_HOSTKEY_ZENITY"); zenity != "" {
		cfg.zenity = zenity
	}
	return cfg, nil
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

// hostIdentity unwraps with every host key, and releases a file key only
// after approval. Files not encrypted to a host key never trigger a prompt.
type hostIdentity struct {
	cfg  config
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
		decision, err := approve(h.cfg, key.recipient)
		fmt.Fprintf(h.log, "age-plugin-hostkey: %s %s: %s\n",
			time.Now().Format(time.RFC3339), key.recipient, decision)
		if err != nil {
			return nil, err
		}
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

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-plugin-hostkey: %v\n", err)
		return 1
	}

	if *printID {
		keys, err := loadKeys(cfg.keyFile)
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
		keys, err := loadKeys(cfg.keyFile)
		if err != nil {
			return nil, err
		}
		return &hostIdentity{cfg: cfg, keys: keys, log: os.Stderr}, nil
	})
	return p.Main()
}

func main() {
	os.Exit(run())
}

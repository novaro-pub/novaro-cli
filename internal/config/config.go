// Package config keeps what novaro login made: the API's address, the
// market, the device's name and the key, the key in the OS keychain when
// there is one and in the config file (0600) when there is none.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	// keyringService and keyringUser name novaro's one entry in the OS
	// keychain: one login at a time, so a login against another API
	// address replaces the key rather than leaving the old one behind.
	keyringService = "novaro"
	keyringUser    = "api-key"
)

// Profile is the config file's content.
type Profile struct {
	APIBase    string `json:"api_base"`
	Market     string `json:"market"`
	DeviceName string `json:"device_name,omitempty"`
	KeyPrefix  string `json:"key_prefix,omitempty"`
	// KeyExpiresAt is unix seconds; 0 for a key that does not expire.
	KeyExpiresAt int64 `json:"key_expires_at,omitempty"`
	// Key is set only when no keychain took it.
	Key string `json:"key,omitempty"`
	// ListenSecret is the signing secret novaro listen last got with this
	// login's key (ListenKeyPrefix) on this device (ListenDevice, "" for a
	// CLI key, which names its own): what listen --print-secret prints
	// without opening a session, which would replace a running listen's.
	ListenSecret    string `json:"listen_secret,omitempty"`
	ListenKeyPrefix string `json:"listen_key_prefix,omitempty"`
	ListenDevice    string `json:"listen_device,omitempty"`
}

// Store reads and writes the profile and its key.
type Store struct {
	// Path is the config file.
	Path string
	// Keyring is the OS keychain; tests replace it.
	Keyring Keyring
}

// Keyring is the part of go-keyring novaro uses.
type Keyring interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (osKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (osKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// Default is the store in the user's config directory, or in
// $NOVARO_CONFIG_DIR when set.
func Default() (*Store, error) {
	dir := os.Getenv("NOVARO_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("no config directory (set NOVARO_CONFIG_DIR): %w", err)
		}
		dir = filepath.Join(base, "novaro")
	}
	return &Store{Path: filepath.Join(dir, "config.json"), Keyring: osKeyring{}}, nil
}

// ErrNotLoggedIn is Load's answer when login has not run.
var ErrNotLoggedIn = errors.New("not logged in: run novaro login, or pass --api-key")

// readProfile reads the config file alone.
func (s *Store) readProfile() (Profile, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Profile{}, ErrNotLoggedIn
	}
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("%s: %w (novaro logout removes it)", s.Path, err)
	}
	return p, nil
}

// Load reads the profile and its key.
func (s *Store) Load() (Profile, string, error) {
	p, err := s.readProfile()
	if err != nil {
		return Profile{}, "", err
	}
	if p.Key != "" {
		return p, p.Key, nil
	}
	key, err := s.Keyring.Get(keyringService, keyringUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return p, "", ErrNotLoggedIn
	}
	if err != nil {
		return p, "", fmt.Errorf("the OS keychain: %w", err)
	}
	return p, key, nil
}

// Save writes p and key: key to the keychain, or into the file when the
// keychain refuses it (a server without one); inFile says which. A file
// that cannot be written takes the key back out of the keychain.
func (s *Store) Save(p Profile, key string) (inFile bool, err error) {
	p.Key = ""
	if err := s.Keyring.Set(keyringService, keyringUser, key); err != nil {
		p.Key = key
		inFile = true
	}
	if err := s.write(p); err != nil {
		if !inFile {
			_ = s.Keyring.Delete(keyringService, keyringUser)
		}
		return false, err
	}
	return inFile, nil
}

// Profile reads the profile alone, not the key: no keychain prompt.
func (s *Store) Profile() (Profile, error) { return s.readProfile() }

// SetListenSecret keeps the signing secret listen got with the key of
// keyPrefix on device, in login's profile, when that key is still login's
// (a listen started before another login keeps its secret to itself).
func (s *Store) SetListenSecret(keyPrefix, device, secret string) error {
	p, err := s.readProfile()
	if err != nil {
		return err
	}
	if p.KeyPrefix != keyPrefix {
		return nil
	}
	if p.ListenSecret == secret && p.ListenKeyPrefix == keyPrefix && p.ListenDevice == device {
		return nil
	}
	p.ListenSecret, p.ListenKeyPrefix, p.ListenDevice = secret, keyPrefix, device
	return s.write(p)
}

// ListenSecretFor is the secret kept for the key of keyPrefix on device,
// "" for none.
func (p Profile) ListenSecretFor(keyPrefix, device string) string {
	if p.ListenSecret == "" || p.ListenKeyPrefix != keyPrefix || p.ListenDevice != device {
		return ""
	}
	return p.ListenSecret
}

// write replaces the file with p, 0600, whole: a new file renamed over it.
func (s *Store) write(p Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.Path)
}

// Clear removes the key and the profile, whatever state they are in. A
// key in the keychain goes first: if the keychain cannot be reached, the
// file stays, so logout can be run again. A key in the file, or a file
// that cannot be read, goes with the file, and a keychain that cannot be
// reached then only means there was nothing of novaro's in it to remove.
// Neither being there is not an error.
func (s *Store) Clear() error {
	p, readErr := s.readProfile()
	if errors.Is(readErr, ErrNotLoggedIn) {
		return nil
	}
	if readErr == nil && p.Key == "" {
		err := s.Keyring.Delete(keyringService, keyringUser)
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("the OS keychain: %w (the key is still there; run novaro logout again)", err)
		}
	} else {
		_ = s.Keyring.Delete(keyringService, keyringUser)
	}
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Expired says whether p's key has expired at now.
func (p Profile) Expired(now time.Time) bool {
	return p.KeyExpiresAt != 0 && !now.Before(time.Unix(p.KeyExpiresAt, 0))
}
